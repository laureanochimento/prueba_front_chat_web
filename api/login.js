const bcrypt = require('bcryptjs');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const SECRET = process.env.SESSION_SECRET || 'engine-secret-2024';

// ── Rate limiting (en memoria, por IP) ────────────────────────────
// Estructura: { ip: { count: N, firstAttempt: timestamp } }
const rateLimitMap = {};
const MAX_ATTEMPTS = 5;
const WINDOW_MS    = 15 * 60 * 1000; // 15 minutos

function checkRateLimit(ip) {
  const now = Date.now();
  const record = rateLimitMap[ip];

  // Sin historial o ventana expirada → resetear
  if (!record || now - record.firstAttempt > WINDOW_MS) {
    rateLimitMap[ip] = { count: 0, firstAttempt: now };
    return { blocked: false, remaining: MAX_ATTEMPTS };
  }

  if (record.count >= MAX_ATTEMPTS) {
    const retryAfter = Math.ceil((WINDOW_MS - (now - record.firstAttempt)) / 1000 / 60);
    return { blocked: true, retryAfter };
  }

  return { blocked: false, remaining: MAX_ATTEMPTS - record.count };
}

function registerFailedAttempt(ip) {
  const now = Date.now();
  const record = rateLimitMap[ip];
  if (!record || now - record.firstAttempt > WINDOW_MS) {
    rateLimitMap[ip] = { count: 1, firstAttempt: now };
  } else {
    rateLimitMap[ip].count += 1;
  }
}

function clearAttempts(ip) {
  delete rateLimitMap[ip];
}

// Limpiar IPs viejas cada hora para no acumular memoria
setInterval(() => {
  const now = Date.now();
  for (const ip of Object.keys(rateLimitMap)) {
    if (now - rateLimitMap[ip].firstAttempt > WINDOW_MS) {
      delete rateLimitMap[ip];
    }
  }
}, 60 * 60 * 1000);

// ── Token ─────────────────────────────────────────────────────────
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

// ── DB ────────────────────────────────────────────────────────────
function readDB() {
  const filePath = path.join(process.cwd(), 'data', 'users.json');
  return JSON.parse(fs.readFileSync(filePath, 'utf8'));
}

// ── Handler ───────────────────────────────────────────────────────
module.exports = async (req, res) => {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Método no permitido' });

  // Obtener IP real (Vercel pasa la IP en este header)
  const ip = req.headers['x-forwarded-for']?.split(',')[0]?.trim() || 'unknown';

  // Verificar rate limit ANTES de procesar
  const limit = checkRateLimit(ip);
  if (limit.blocked) {
    return res.status(429).json({
      error: `Demasiados intentos fallidos. Intentá de nuevo en ${limit.retryAfter} minuto${limit.retryAfter === 1 ? '' : 's'}.`
    });
  }

  const { username, password } = req.body;
  if (!username || !password) {
    return res.status(400).json({ error: 'Usuario y contraseña requeridos' });
  }

  let db;
  try { db = readDB(); }
  catch { return res.status(500).json({ error: 'Error interno del servidor' }); }

  const user = db.users.find(u => u.username.toLowerCase() === username.toLowerCase().trim());

  // Usuario no existe → contar como intento fallido
  if (!user) {
    registerFailedAttempt(ip);
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  }

  const valid = await bcrypt.compare(password, user.password);

  // Contraseña incorrecta → contar como intento fallido
  if (!valid) {
    registerFailedAttempt(ip);
    const remaining = MAX_ATTEMPTS - (rateLimitMap[ip]?.count || 0);
    const msg = remaining > 0
      ? `Usuario o contraseña incorrectos. Te quedan ${remaining} intento${remaining === 1 ? '' : 's'}.`
      : `Demasiados intentos fallidos. Intentá de nuevo en 15 minutos.`;
    return res.status(401).json({ error: msg });
  }

  // Login exitoso → limpiar intentos fallidos
  clearAttempts(ip);

  const token = generateToken(user);
  return res.status(200).json({ token, username: user.username, name: user.name || user.username });
};
