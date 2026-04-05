const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'engine-secret-2024';

function generateToken(username) {
  const payload = {
    username,
    exp: Date.now() + 15 * 60 * 1000 // 15 minutos
  };
  const data = JSON.stringify(payload);
  const encoded = Buffer.from(data).toString('base64');
  const sig = crypto.createHmac('sha256', SECRET).update(encoded).digest('hex');
  return `${encoded}.${sig}`;
}

module.exports = async (req, res) => {
  // CORS headers
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  const { username, password } = req.body;

  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }

  // Leer users.json
  let users;
  try {
    const filePath = path.join(process.cwd(), 'data', 'users.json');
    const raw = fs.readFileSync(filePath, 'utf8');
    users = JSON.parse(raw).users;
  } catch (e) {
    console.error('Error leyendo users.json:', e);
    return res.status(500).json({ error: 'Error interno del servidor' });
  }

  // Buscar usuario
  const user = users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());

  if (!user) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  // Validar contraseña
  const valid = await bcrypt.compare(password, user.password);

  if (!valid) {
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  // Generar token y responder
  const token = generateToken(user.username);
  return res.status(200).json({ token, username: user.username });
};
