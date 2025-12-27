/*
  Simple Express + Socket.IO scaffold
  - SQLite (data.db) for persistence
  - JWT auth for admin endpoints
  - Basic users CRUD + presence via socket
  - Admin file load/save endpoints (writes inside project workspace only)

  WARNING: file save endpoint writes to filesystem. Use with care.
*/

const express = require('express');
const http = require('http');
const path = require('path');
const fs = require('fs');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const multer = require('multer');
const { Server } = require('socket.io');
const sqlite3 = require('sqlite3').verbose();

const JWT_SECRET = process.env.JWT_SECRET || 'change_this_secret';
const PORT = process.env.PORT || 4000;
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: '*' } });

app.use(cors());
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true }));

// open sqlite
const DB_FILE = path.join(process.cwd(), 'data.db');
const db = new sqlite3.Database(DB_FILE);

function runAsync(sql, params=[]) {
  return new Promise((resolve, reject) => db.run(sql, params, function(err){ if(err) reject(err); else resolve(this); }));
}
function allAsync(sql, params=[]) {
  return new Promise((resolve, reject) => db.all(sql, params, (err, rows)=> err?reject(err):resolve(rows)));
}
function getAsync(sql, params=[]) {
  return new Promise((resolve, reject) => db.get(sql, params, (err, row)=> err?reject(err):resolve(row)));
}

// init tables
async function initDB(){
  await runAsync(`CREATE TABLE IF NOT EXISTS admins (id INTEGER PRIMARY KEY AUTOINCREMENT, email TEXT UNIQUE, password TEXT, name TEXT, role TEXT)`);
  await runAsync(`CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE, role TEXT, status TEXT, verified INTEGER, kyc TEXT, created INTEGER)`);
  await runAsync(`CREATE TABLE IF NOT EXISTS pages (id INTEGER PRIMARY KEY AUTOINCREMENT, slug TEXT UNIQUE, title TEXT, content TEXT, created INTEGER)`);
  await runAsync(`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, title TEXT, description TEXT, price REAL, category TEXT, featured INTEGER DEFAULT 0, created INTEGER)`);
  await runAsync(`CREATE TABLE IF NOT EXISTS orders (id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, product_id INTEGER, amount REAL, status TEXT, created INTEGER)`);

  // seed admin if none
  const admin = await getAsync('SELECT * FROM admins LIMIT 1');
  if(!admin){
    const pw = await bcrypt.hash('password', 10);
    await runAsync('INSERT INTO admins(email,password,name,role) VALUES(?,?,?,?)',['admin@local', pw, 'Admin', 'super']);
    console.log('Seeded admin@local with password "password"');
  }
}

initDB().catch(e=>{ console.error('DB init failed', e); process.exit(1); });

// auth middleware
function authMiddleware(req, res, next){
  const auth = req.headers.authorization;
  if(!auth) return res.status(401).json({ error:'missing auth' });
  const parts = auth.split(' ');
  if(parts.length!==2) return res.status(401).json({ error:'bad auth header' });
  const token = parts[1];
  try{
    const payload = jwt.verify(token, JWT_SECRET);
    req.admin = payload; next();
  }catch(e){ return res.status(401).json({ error:'invalid token' }); }
}

// --- Auth ---
app.post('/api/auth/login', async (req, res)=>{
  const { email, password } = req.body || {};
  if(!email || !password) return res.status(400).json({ error:'email and password required' });
  try{
    const a = await getAsync('SELECT * FROM admins WHERE email=?', [email]);
    if(!a) return res.status(401).json({ error:'invalid' });
    const ok = await bcrypt.compare(password, a.password);
    if(!ok) return res.status(401).json({ error:'invalid' });
    const token = jwt.sign({ id: a.id, email: a.email, name: a.name, role: a.role }, JWT_SECRET, { expiresIn: '8h' });
    return res.json({ token, admin: { id: a.id, email: a.email, name: a.name, role: a.role } });
  }catch(e){ console.error(e); res.status(500).json({ error:'server' }); }
});

// --- Users endpoints ---
app.get('/api/users', authMiddleware, async (req, res)=>{
  const q = 'SELECT id,name,email,role,status,verified,kyc,created FROM users ORDER BY created DESC';
  const users = await allAsync(q);
  res.json(users);
});

app.post('/api/users', authMiddleware, async (req, res)=>{
  const { name, email, role } = req.body || {};
  if(!name || !email) return res.status(400).json({ error:'name,email required' });
  try{
    await runAsync('INSERT INTO users(name,email,role,status,verified,kyc,created) VALUES(?,?,?,?,?,?,?)', [name, email.toLowerCase(), role||'buyer', 'active', 0, 'unverified', Date.now()]);
    const u = await getAsync('SELECT id,name,email,role,status,verified,kyc,created FROM users WHERE email=?',[email.toLowerCase()]);
    res.json(u);
  }catch(e){ console.error(e); res.status(500).json({ error:'db' }); }
});

app.put('/api/users/:id', authMiddleware, async (req, res)=>{
  const id = req.params.id; const { name, email, role, status, verified, kyc } = req.body || {};
  try{
    await runAsync('UPDATE users SET name=?, email=?, role=?, status=?, verified=?, kyc=? WHERE id=?',[name, email?.toLowerCase(), role, status, verified?1:0, kyc, id]);
    const u = await getAsync('SELECT id,name,email,role,status,verified,kyc,created FROM users WHERE id=?',[id]);
    res.json(u);
  }catch(e){ console.error(e); res.status(500).json({ error:'db' }); }
});

app.delete('/api/users/:id', authMiddleware, async (req, res)=>{
  const id = req.params.id;
  try{ await runAsync('DELETE FROM users WHERE id=?',[id]); res.json({ ok:true }); }catch(e){ res.status(500).json({ error:'db' }); }
});

// --- Pages (content) ---
app.get('/api/pages', async (req,res)=>{ const pages = await allAsync('SELECT * FROM pages'); res.json(pages); });
app.get('/api/pages/:slug', async (req,res)=>{ const p = await getAsync('SELECT * FROM pages WHERE slug=?',[req.params.slug]); if(!p) return res.status(404).json({}); res.json(p); });
app.post('/api/pages', authMiddleware, async (req,res)=>{ const { slug,title,content } = req.body||{}; if(!slug) return res.status(400).json({ error:'slug required' }); await runAsync('INSERT INTO pages(slug,title,content,created) VALUES(?,?,?,?)',[slug,title||'',content||'',Date.now()]); res.json({ok:true}); });
app.put('/api/pages/:id', authMiddleware, async (req,res)=>{ const { title, content } = req.body||{}; await runAsync('UPDATE pages SET title=?,content=? WHERE id=?',[title,content,req.params.id]); res.json({ok:true}); });
app.delete('/api/pages/:id', authMiddleware, async (req,res)=>{ await runAsync('DELETE FROM pages WHERE id=?',[req.params.id]); res.json({ok:true}); });

// --- Products endpoints (minimal) ---
app.get('/api/products', async (req,res)=>{ const rows = await allAsync('SELECT * FROM products ORDER BY created DESC'); res.json(rows); });
app.post('/api/products', authMiddleware, async (req,res)=>{ const { title, description, price, category, featured } = req.body||{}; await runAsync('INSERT INTO products(title,description,price,category,featured,created) VALUES(?,?,?,?,?,?)',[title,description,price||0,category||'', featured?1:0,Date.now()]); res.json({ok:true}); });
app.put('/api/products/:id', authMiddleware, async (req,res)=>{ const { title, description, price, category, featured } = req.body||{}; await runAsync('UPDATE products SET title=?,description=?,price=?,category=?,featured=? WHERE id=?',[title,description,price,category,featured?1:0,req.params.id]); res.json({ok:true}); });
app.delete('/api/products/:id', authMiddleware, async (req,res)=>{ await runAsync('DELETE FROM products WHERE id=?',[req.params.id]); res.json({ok:true}); });

// --- Orders (minimal) ---
app.get('/api/orders', authMiddleware, async (req,res)=>{ const rows = await allAsync('SELECT * FROM orders ORDER BY created DESC'); res.json(rows); });
app.put('/api/orders/:id', authMiddleware, async (req,res)=>{ const { status } = req.body||{}; await runAsync('UPDATE orders SET status=? WHERE id=?',[status,req.params.id]); res.json({ok:true}); });

// --- Admin file load/save (careful) ---
// Only allow paths inside workspace
function safePath(target){
  const base = process.cwd();
  const resolved = path.normalize(path.join(base, target));
  if(!resolved.startsWith(base)) throw new Error('invalid path');
  return resolved;
}

app.get('/api/admin/load', authMiddleware, async (req,res)=>{
  const p = req.query.path;
  if(!p) return res.status(400).json({ error:'path required' });
  try{
    const full = safePath(p);
    const text = fs.readFileSync(full, 'utf8');
    res.type('text/plain').send(text);
  }catch(e){ res.status(400).json({ error: e.message }); }
});

app.post('/api/admin/save', authMiddleware, async (req,res)=>{
  const { path: p, content } = req.body||{};
  if(!p) return res.status(400).json({ error:'path required' });
  try{
    const full = safePath(p);
    fs.writeFileSync(full, content, 'utf8');
    res.json({ message:'saved' });
  }catch(e){ res.status(400).json({ error: e.message }); }
});

// file uploads (images)
const upload = multer({ dest: path.join(process.cwd(),'uploads/') });
app.post('/api/upload', authMiddleware, upload.single('file'), (req,res)=>{
  if(!req.file) return res.status(400).json({ error:'no file' });
  // return relative path
  const rel = path.relative(process.cwd(), req.file.path);
  res.json({ path: '/' + rel.replace(/\\/g,'/') });
});

// basic stats
app.get('/api/stats', authMiddleware, async (req,res)=>{
  const users = await allAsync('SELECT COUNT(*) as c FROM users');
  const products = await allAsync('SELECT COUNT(*) as c FROM products');
  const orders = await allAsync('SELECT COUNT(*) as c FROM orders');
  const revenueRow = await getAsync('SELECT SUM(amount) as s FROM orders');
  res.json({ users: users[0].c, products: products[0].c, orders: orders[0].c, revenue: revenueRow.s||0 });
});

// serve a small health endpoint
app.get('/api/health', (req,res)=> res.json({ ok:true, env: process.env.NODE_ENV||'development' }));

// --- Socket.io for admin presence ---
const adminClients = new Map(); // socketId -> {id,email,name,role}
function broadcastOnline(){
  const arr = Array.from(adminClients.values()).map(a=>({ id: a.id, email: a.email, name: a.name, role: a.role }));
  io.emit('online', { users: arr });
}

io.on('connection', (socket)=>{
  // accept token via query or auth message
  const token = socket.handshake.query && socket.handshake.query.token;
  if(token){
    try{
      const payload = jwt.verify(token, JWT_SECRET);
      adminClients.set(socket.id, payload);
      broadcastOnline();
    }catch(e){ /* ignore */ }
  }

  socket.on('auth', (data)=>{
    try{ const payload = jwt.verify(data.token, JWT_SECRET); adminClients.set(socket.id, payload); broadcastOnline(); }catch(e){}
  });

  socket.on('disconnect', ()=>{ adminClients.delete(socket.id); broadcastOnline(); });
});

// start server
server.listen(PORT, ()=>{ console.log('Server running on port', PORT); });

// graceful shutdown
process.on('SIGINT', ()=>{ console.log('shutting down'); server.close(()=>process.exit(0)); });
