const http = require('http');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const { URL } = require('url');

const PORT = process.env.PORT || 3000;
const ROOT = path.join(__dirname, '..');
const PUBLIC_DIR = path.join(ROOT, 'public');
const DATA_DIR = path.join(__dirname, 'data');
const USERS_FILE = path.join(DATA_DIR, 'users.json');
const MESSAGES_FILE = path.join(DATA_DIR, 'messages.json');
const PRODUCTS_FILE = path.join(DATA_DIR, 'products.json');

// In-memory session store: token -> { userId, expires }
// (Fine for a demo/single-process server. Swap for a real session store or JWT in production.)
const sessions = new Map();
const SESSION_TTL_MS = 1000 * 60 * 60 * 24 * 7; // 7 days

// ---------- tiny JSON "database" helpers ----------
function readJSON(file, fallback) {
  try {
    const raw = fs.readFileSync(file, 'utf8').trim();
    return raw ? JSON.parse(raw) : fallback;
  } catch (err) {
    if (err.code === 'ENOENT') return fallback;
    throw err;
  }
}

function writeJSON(file, data) {
  fs.writeFileSync(file, JSON.stringify(data, null, 2));
}

// ---------- password hashing (scrypt, no external deps) ----------
function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, stored) {
  const [salt, hash] = stored.split(':');
  const check = crypto.scryptSync(password, salt, 64).toString('hex');
  return crypto.timingSafeEqual(Buffer.from(hash, 'hex'), Buffer.from(check, 'hex'));
}

function createSession(userId) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions.set(token, { userId, expires: Date.now() + SESSION_TTL_MS });
  return token;
}

function getSession(token) {
  const session = sessions.get(token);
  if (!session) return null;
  if (session.expires < Date.now()) {
    sessions.delete(token);
    return null;
  }
  return session;
}

// ---------- request helpers ----------
function sendJSON(res, status, body) {
  const payload = JSON.stringify(body);
  res.writeHead(status, {
    'Content-Type': 'application/json; charset=utf-8',
    'Content-Length': Buffer.byteLength(payload),
  });
  res.end(payload);
}

function readBody(req) {
  return new Promise((resolve, reject) => {
    let data = '';
    let size = 0;
    const LIMIT = 1e6; // 1MB cap
    req.on('data', (chunk) => {
      size += chunk.length;
      if (size > LIMIT) {
        reject(Object.assign(new Error('Payload too large'), { status: 413 }));
        req.destroy();
        return;
      }
      data += chunk;
    });
    req.on('end', () => {
      if (!data) return resolve({});
      try {
        resolve(JSON.parse(data));
      } catch {
        reject(Object.assign(new Error('Invalid JSON'), { status: 400 }));
      }
    });
    req.on('error', reject);
  });
}

function getBearerToken(req) {
  const header = req.headers['authorization'] || '';
  const [scheme, token] = header.split(' ');
  return scheme === 'Bearer' && token ? token : null;
}

function isValidEmail(email) {
  return typeof email === 'string' && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

// ---------- API route handlers ----------
const api = {
  async 'GET /api/products'(req, res) {
    const products = readJSON(PRODUCTS_FILE, []);
    sendJSON(res, 200, { products });
  },

  async 'POST /api/contact'(req, res) {
    const body = await readBody(req);
    const name = (body.name || '').trim();
    const email = (body.email || '').trim();
    const message = (body.message || '').trim();

    const errors = {};
    if (!name) errors.name = 'Name is required.';
    if (!isValidEmail(email)) errors.email = 'Enter a valid email.';
    if (!message) errors.message = 'Message can\u2019t be empty.';
    if (Object.keys(errors).length) return sendJSON(res, 422, { ok: false, errors });

    const messages = readJSON(MESSAGES_FILE, []);
    const entry = {
      id: crypto.randomUUID(),
      name,
      email,
      message,
      createdAt: new Date().toISOString(),
    };
    messages.push(entry);
    writeJSON(MESSAGES_FILE, messages);

    sendJSON(res, 201, { ok: true, message: 'Thanks — we\u2019ll get back to you within a day.' });
  },

  async 'POST /api/register'(req, res) {
    const body = await readBody(req);
    const name = (body.name || '').trim();
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';

    const errors = {};
    if (!name) errors.name = 'Name is required.';
    if (!isValidEmail(email)) errors.email = 'Enter a valid email.';
    if (!password || password.length < 8) errors.password = 'Password must be at least 8 characters.';
    if (Object.keys(errors).length) return sendJSON(res, 422, { ok: false, errors });

    const users = readJSON(USERS_FILE, []);
    if (users.some((u) => u.email === email)) {
      return sendJSON(res, 409, { ok: false, errors: { email: 'An account with that email already exists.' } });
    }

    const user = {
      id: crypto.randomUUID(),
      name,
      email,
      passwordHash: hashPassword(password),
      createdAt: new Date().toISOString(),
    };
    users.push(user);
    writeJSON(USERS_FILE, users);

    const token = createSession(user.id);
    sendJSON(res, 201, { ok: true, token, user: { id: user.id, name: user.name, email: user.email } });
  },

  async 'POST /api/login'(req, res) {
    const body = await readBody(req);
    const email = (body.email || '').trim().toLowerCase();
    const password = body.password || '';

    const users = readJSON(USERS_FILE, []);
    const user = users.find((u) => u.email === email);
    if (!user || !verifyPassword(password, user.passwordHash)) {
      return sendJSON(res, 401, { ok: false, error: 'Incorrect email or password.' });
    }

    const token = createSession(user.id);
    sendJSON(res, 200, { ok: true, token, user: { id: user.id, name: user.name, email: user.email } });
  },

  async 'POST /api/logout'(req, res) {
    const token = getBearerToken(req);
    if (token) sessions.delete(token);
    sendJSON(res, 200, { ok: true });
  },

  async 'GET /api/me'(req, res) {
    const token = getBearerToken(req);
    const session = token && getSession(token);
    if (!session) return sendJSON(res, 401, { ok: false, error: 'Not logged in.' });

    const users = readJSON(USERS_FILE, []);
    const user = users.find((u) => u.id === session.userId);
    if (!user) return sendJSON(res, 401, { ok: false, error: 'Not logged in.' });

    sendJSON(res, 200, { ok: true, user: { id: user.id, name: user.name, email: user.email } });
  },
};

// ---------- static file serving ----------
const MIME_TYPES = {
  '.html': 'text/html; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.js': 'application/javascript; charset=utf-8',
  '.json': 'application/json; charset=utf-8',
  '.svg': 'image/svg+xml',
  '.png': 'image/png',
  '.jpg': 'image/jpeg',
  '.ico': 'image/x-icon',
};

function serveStatic(req, res, pathname) {
  let filePath = pathname === '/' ? '/index.html' : pathname;
  filePath = path.normalize(filePath).replace(/^(\.\.[/\\])+/, '');
  let fullPath = path.join(PUBLIC_DIR, filePath);

  // Guard against path traversal escaping the public dir.
  if (!fullPath.startsWith(PUBLIC_DIR)) {
    return sendJSON(res, 400, { ok: false, error: 'Bad request.' });
  }

  fs.stat(fullPath, (err, stat) => {
    if (err || !stat.isFile()) {
      // Friendly fallback: try adding .html (so /about works like /about.html)
      const withHtml = `${fullPath}.html`;
      return fs.stat(withHtml, (err2, stat2) => {
        if (!err2 && stat2.isFile()) return streamFile(res, withHtml);
        serveNotFound(res);
      });
    }
    streamFile(res, fullPath);
  });
}

function streamFile(res, fullPath) {
  const ext = path.extname(fullPath).toLowerCase();
  res.writeHead(200, { 'Content-Type': MIME_TYPES[ext] || 'application/octet-stream' });
  fs.createReadStream(fullPath).pipe(res);
}

function serveNotFound(res) {
  const notFoundPage = path.join(PUBLIC_DIR, '404.html');
  fs.stat(notFoundPage, (err, stat) => {
    if (!err && stat.isFile()) {
      res.writeHead(404, { 'Content-Type': 'text/html; charset=utf-8' });
      fs.createReadStream(notFoundPage).pipe(res);
    } else {
      res.writeHead(404, { 'Content-Type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
    }
  });
}

// ---------- server ----------
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, `http://${req.headers.host}`);
  const routeKey = `${req.method} ${url.pathname}`;

  if (url.pathname.startsWith('/api/')) {
    const handler = api[routeKey];
    if (!handler) return sendJSON(res, 404, { ok: false, error: 'Unknown API route.' });
    try {
      await handler(req, res);
    } catch (err) {
      const status = err.status || 500;
      sendJSON(res, status, { ok: false, error: status === 500 ? 'Server error.' : err.message });
    }
    return;
  }

  if (req.method === 'GET' || req.method === 'HEAD') {
    return serveStatic(req, res, url.pathname);
  }

  sendJSON(res, 405, { ok: false, error: 'Method not allowed.' });
});

server.listen(PORT, () => {
  console.log(`SIGNAL server running at http://localhost:${PORT}`);
});