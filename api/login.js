const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'engine-secret-2024';

function generateToken(user) {
  const payload = {
    username: user.username,
    name: user.name || user.username,
    dify_api_key: user.dify_api_key,
    exp: Date.now() + 15 * 60 * 1000
  };
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = crypto.createHmac('sha256', SECRET).update(encoded).digest('hex');
  return `${encoded}.${sig}`;
}

function readDB() {
  const filePath = path.join(process.cwd(), 'data', 'users.json');
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  const { username, password } = req.body;
  if (!username || !password)
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });

  let db;
  try { db = readDB(); }
  catch (e) { return res.status(500).json({ error: 'Error interno del servidor' }); }

  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());
  if (!user) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

  const valid = await bcrypt.compare(password, user.password);
  if (!valid) return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });

  const token = generateToken(user);
  return res.status(200).json({ token, username: user.username, name: user.name || user.username });
};
