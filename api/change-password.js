const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'engine-secret-2024';
const DB_PATH = path.join(process.cwd(), 'data', 'users.json');

function readDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function writeDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}

function verifyUserToken(token) {
  if (!token) return null;
  try {
    const [encoded, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', SECRET).update(encoded).digest('hex');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
    if (Date.now() > payload.exp) return null;
    return payload;
  } catch { return null; }
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).end();

  // Verificar token de sesión del usuario
  const auth = req.headers['authorization'] || '';
  const token = auth.startsWith('Bearer ') ? auth.slice(7) : null;
  const payload = verifyUserToken(token);
  if (!payload) return res.status(401).json({ error: 'Sesión inválida o expirada' });

  const { current_password, new_password } = req.body;
  if (!current_password || !new_password)
    return res.status(400).json({ error: 'Campos requeridos' });
  if (new_password.length < 8)
    return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres' });

  let db;
  try { db = readDB(); } catch { return res.status(500).json({ error: 'Error interno' }); }

  const idx = db.users.findIndex(u => u.username === payload.username);
  if (idx === -1) return res.status(404).json({ error: 'Usuario no encontrado' });

  const valid = await bcrypt.compare(current_password, db.users[idx].password);
  if (!valid) return res.status(401).json({ error: 'Contraseña actual incorrecta' });

  db.users[idx].password = await bcrypt.hash(new_password, 10);
  try { writeDB(db); } catch { return res.status(500).json({ error: 'Error guardando' }); }

  return res.status(200).json({ ok: true, message: 'Contraseña actualizada correctamente' });
};
