const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'engine-secret-2024';
const DB_PATH = path.join(process.cwd(), 'data', 'users.json');

// ── DB helpers ─────────────────────────────────────────────────────
function readDB() {
  return JSON.parse(fs.readFileSync(DB_PATH, 'utf8'));
}
function writeDB(db) {
  fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2), 'utf8');
}

// ── Token helpers ──────────────────────────────────────────────────
function generateAdminToken(username) {
  const payload = { username, role: 'admin', exp: Date.now() + 60 * 60 * 1000 }; // 1h
  const encoded = Buffer.from(JSON.stringify(payload)).toString('base64');
  const sig = crypto.createHmac('sha256', SECRET).update(encoded).digest('hex');
  return `${encoded}.${sig}`;
}

function verifyAdminToken(token) {
  if (!token) return null;
  try {
    const [encoded, sig] = token.split('.');
    const expected = crypto.createHmac('sha256', SECRET).update(encoded).digest('hex');
    if (sig !== expected) return null;
    const payload = JSON.parse(Buffer.from(encoded, 'base64').toString('utf8'));
    if (Date.now() > payload.exp) return null;
    if (payload.role !== 'admin') return null;
    return payload;
  } catch { return null; }
}

function getTokenFromHeader(req) {
  const auth = req.headers['authorization'] || '';
  return auth.startsWith('Bearer ') ? auth.slice(7) : null;
}

// ── Main handler ───────────────────────────────────────────────────
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, PUT, DELETE, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  if (req.method === 'OPTIONS') return res.status(200).end();

  const { action } = req.query;

  // ── POST /api/admin?action=login ───────────────────────────────
  if (action === 'login') {
    if (req.method !== 'POST') return res.status(405).end();
    const { username, password } = req.body;
    if (!username || !password)
      return res.status(400).json({ error: 'Campos requeridos' });

    let db;
    try { db = readDB(); } catch { return res.status(500).json({ error: 'Error leyendo DB' }); }

    const admin = db.admins.find(a => a.username.toLowerCase() === username.toLowerCase().trim());
    if (!admin) return res.status(401).json({ error: 'Credenciales incorrectas' });

    const valid = await bcrypt.compare(password, admin.password);
    if (!valid) return res.status(401).json({ error: 'Credenciales incorrectas' });

    const token = generateAdminToken(admin.username);
    return res.status(200).json({ token, username: admin.username });
  }

  // ── Todas las acciones siguientes requieren token de admin ─────
  const adminPayload = verifyAdminToken(getTokenFromHeader(req));
  if (!adminPayload) return res.status(401).json({ error: 'No autorizado' });

  let db;
  try { db = readDB(); } catch { return res.status(500).json({ error: 'Error leyendo DB' }); }

  // ── GET /api/admin?action=list ─────────────────────────────────
  if (action === 'list') {
    const safeUsers = db.users.map(({ password, ...rest }) => rest);
    return res.status(200).json({ users: safeUsers });
  }

  // ── POST /api/admin?action=create ─────────────────────────────
  if (action === 'create') {
    if (req.method !== 'POST') return res.status(405).end();
    const { username, password, name, dify_api_key } = req.body;

    if (!username || !password || !name)
      return res.status(400).json({ error: 'username, password y name son requeridos' });

    const exists = db.users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());
    if (exists) return res.status(409).json({ error: 'El usuario ya existe' });

    const hashed = await bcrypt.hash(password, 10);
    db.users.push({
      username: username.trim(),
      password: hashed,
      name: name.trim(),
      dify_api_key: dify_api_key || ''
    });

    try { writeDB(db); } catch { return res.status(500).json({ error: 'Error guardando DB' }); }
    return res.status(201).json({ ok: true, message: 'Usuario creado' });
  }

  // ── PUT /api/admin?action=update ───────────────────────────────
  if (action === 'update') {
    if (req.method !== 'PUT') return res.status(405).end();
    const { username, name, dify_api_key, new_password } = req.body;

    if (!username) return res.status(400).json({ error: 'username requerido' });

    const idx = db.users.findIndex(u => u.username.toLowerCase() === username.toLowerCase().trim());
    if (idx === -1) return res.status(404).json({ error: 'Usuario no encontrado' });

    if (name) db.users[idx].name = name.trim();
    if (dify_api_key !== undefined) db.users[idx].dify_api_key = dify_api_key;
    if (new_password) db.users[idx].password = await bcrypt.hash(new_password, 10);

    try { writeDB(db); } catch { return res.status(500).json({ error: 'Error guardando DB' }); }
    return res.status(200).json({ ok: true, message: 'Usuario actualizado' });
  }

  // ── DELETE /api/admin?action=delete ───────────────────────────
  if (action === 'delete') {
    if (req.method !== 'DELETE') return res.status(405).end();
    const { username } = req.body;

    if (!username) return res.status(400).json({ error: 'username requerido' });

    const before = db.users.length;
    db.users = db.users.filter(u => u.username.toLowerCase() !== username.toLowerCase().trim());
    if (db.users.length === before)
      return res.status(404).json({ error: 'Usuario no encontrado' });

    try { writeDB(db); } catch { return res.status(500).json({ error: 'Error guardando DB' }); }
    return res.status(200).json({ ok: true, message: 'Usuario eliminado' });
  }

  // ── PUT /api/admin?action=change-admin-password ────────────────
  if (action === 'change-admin-password') {
    if (req.method !== 'PUT') return res.status(405).end();
    const { current_password, new_password } = req.body;

    if (!current_password || !new_password)
      return res.status(400).json({ error: 'Campos requeridos' });
    if (new_password.length < 8)
      return res.status(400).json({ error: 'La nueva contraseña debe tener al menos 8 caracteres' });

    const adminIdx = db.admins.findIndex(a => a.username === adminPayload.username);
    if (adminIdx === -1) return res.status(404).json({ error: 'Admin no encontrado' });

    const valid = await bcrypt.compare(current_password, db.admins[adminIdx].password);
    if (!valid) return res.status(401).json({ error: 'Contraseña actual incorrecta' });

    db.admins[adminIdx].password = await bcrypt.hash(new_password, 10);
    try { writeDB(db); } catch { return res.status(500).json({ error: 'Error guardando DB' }); }
    return res.status(200).json({ ok: true, message: 'Contraseña de admin actualizada' });
  }

  return res.status(400).json({ error: 'Acción no reconocida' });
};
