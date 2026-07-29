const express = require('express');
const { Pool } = require('pg');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');

const app = express();
const PORT = process.env.PORT || 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'cafe-tueste-secret-2024';
const upload = multer({ storage: multer.memoryStorage() });

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false
});

app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ─── DB INIT ──────────────────────────────────────────────────────────────────
async function initDB() {
  await pool.query(`
    CREATE TABLE IF NOT EXISTS ct_usuarios (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(100) NOT NULL,
      usuario VARCHAR(50) UNIQUE NOT NULL,
      password_hash TEXT NOT NULL,
      rol VARCHAR(20) DEFAULT 'operativo',
      creado_en TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ct_cafe_verde (
      id SERIAL PRIMARY KEY,
      origen VARCHAR(200) NOT NULL,
      variedad VARCHAR(200),
      proceso VARCHAR(100),
      proveedor VARCHAR(200),
      stock_kg NUMERIC(10,2) DEFAULT 0,
      precio_kg NUMERIC(10,2) DEFAULT 0,
      fecha_compra DATE,
      notas TEXT,
      activo BOOLEAN DEFAULT TRUE,
      creado_en TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ct_lotes (
      id SERIAL PRIMARY KEY,
      codigo VARCHAR(50),
      cafe_verde_id INTEGER REFERENCES ct_cafe_verde(id),
      origen_nombre VARCHAR(200),
      peso_verde NUMERIC(8,2) DEFAULT 0,
      peso_tostado NUMERIC(8,2) DEFAULT 0,
      perfil VARCHAR(50),
      fecha_tueste DATE NOT NULL,
      dias_reposo INTEGER DEFAULT 7,
      fecha_lista DATE,
      destino VARCHAR(200),
      cliente VARCHAR(200),
      notas_cata TEXT,
      score_sca NUMERIC(4,1),
      estado VARCHAR(30) DEFAULT 'reposo',
      fuente VARCHAR(20) DEFAULT 'manual',
      creado_en TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ct_productos (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(200) NOT NULL,
      presentacion VARCHAR(100),
      peso_g NUMERIC(8,2),
      precio NUMERIC(10,2) DEFAULT 0,
      activo BOOLEAN DEFAULT TRUE
    );

    CREATE TABLE IF NOT EXISTS ct_clientes (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(200) NOT NULL,
      tipo VARCHAR(50) DEFAULT 'b2b',
      telefono VARCHAR(50),
      email VARCHAR(200),
      direccion TEXT,
      notas TEXT,
      creado_en TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ct_pedidos (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER REFERENCES ct_clientes(id),
      cliente_nombre VARCHAR(200),
      fecha_pedido DATE NOT NULL,
      fecha_entrega DATE,
      total NUMERIC(10,2) DEFAULT 0,
      estado VARCHAR(30) DEFAULT 'pendiente',
      nota TEXT,
      creado_en TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ct_pedido_items (
      id SERIAL PRIMARY KEY,
      pedido_id INTEGER REFERENCES ct_pedidos(id) ON DELETE CASCADE,
      descripcion VARCHAR(300),
      cantidad NUMERIC(8,2),
      unidad VARCHAR(50),
      precio_unitario NUMERIC(10,2),
      subtotal NUMERIC(10,2)
    );

    CREATE TABLE IF NOT EXISTS ct_sucursales (
      id SERIAL PRIMARY KEY,
      nombre VARCHAR(200) NOT NULL,
      ciudad VARCHAR(100),
      direccion TEXT,
      contacto VARCHAR(200),
      telefono VARCHAR(50),
      notas TEXT,
      activo BOOLEAN DEFAULT TRUE,
      creado_en TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ct_entregas_sucursal (
      id SERIAL PRIMARY KEY,
      sucursal_id INTEGER REFERENCES ct_sucursales(id) ON DELETE CASCADE,
      fecha DATE NOT NULL,
      productos TEXT,
      kg_total NUMERIC(8,2),
      estado VARCHAR(30) DEFAULT 'programada',
      notas TEXT,
      creado_en TIMESTAMP DEFAULT NOW()
    );

    CREATE TABLE IF NOT EXISTS ct_cobros (
      id SERIAL PRIMARY KEY,
      cliente_id INTEGER REFERENCES ct_clientes(id),
      cliente_nombre VARCHAR(200),
      pedido_id INTEGER REFERENCES ct_pedidos(id),
      concepto TEXT,
      total NUMERIC(10,2) DEFAULT 0,
      pagado NUMERIC(10,2) DEFAULT 0,
      fecha DATE NOT NULL,
      metodo VARCHAR(50),
      creado_en TIMESTAMP DEFAULT NOW()
    );
  `);

  // Sucursales default
  const { rows: sRows } = await pool.query('SELECT COUNT(*) FROM ct_sucursales');
  if (parseInt(sRows[0].count) === 0) {
    await pool.query(`INSERT INTO ct_sucursales (nombre, ciudad) VALUES ('Mexicali','Mexicali'),('Ensenada','Ensenada')`);
  }

  // Productos default
  const { rows } = await pool.query('SELECT COUNT(*) FROM ct_productos');
  if (parseInt(rows[0].count) === 0) {
    await pool.query(`INSERT INTO ct_productos (nombre, presentacion, peso_g, precio) VALUES
      ('Cafe tostado 250g','bolsa',250,0),
      ('Cafe tostado 500g','bolsa',500,0),
      ('Cafe tostado 1kg','bolsa',1000,0),
      ('Cafe a granel','granel',null,0)`);
  }
  console.log('DB lista.');
}

// ─── AUTH MIDDLEWARE ──────────────────────────────────────────────────────────
function auth(req, res, next) {
  const h = req.headers.authorization;
  if (!h?.startsWith('Bearer ')) return res.status(401).json({ error: 'No autorizado' });
  try { req.user = jwt.verify(h.slice(7), JWT_SECRET); next(); }
  catch { res.status(401).json({ error: 'Token invalido' }); }
}
const adminOnly = (req, res, next) => req.user.rol === 'admin' ? next() : res.status(403).json({ error: 'Solo admin' });

// ─── AUTH ROUTES ──────────────────────────────────────────────────────────────
app.get('/api/auth/status', async (req, res) => {
  const r = await pool.query('SELECT COUNT(*) FROM ct_usuarios');
  res.json({ tieneUsuarios: parseInt(r.rows[0].count) > 0 });
});

app.post('/api/auth/setup', async (req, res) => {
  const { nombre, usuario, password } = req.body;
  const r = await pool.query('SELECT COUNT(*) FROM ct_usuarios');
  if (parseInt(r.rows[0].count) > 0) return res.status(400).json({ error: 'Ya existe admin' });
  const hash = await bcrypt.hash(password, 10);
  await pool.query('INSERT INTO ct_usuarios (nombre,usuario,password_hash,rol) VALUES ($1,$2,$3,$4)', [nombre,usuario,hash,'admin']);
  res.json({ ok: true });
});

app.post('/api/auth/login', async (req, res) => {
  const { usuario, password } = req.body;
  const r = await pool.query('SELECT * FROM ct_usuarios WHERE usuario=$1', [usuario]);
  if (!r.rows.length || !await bcrypt.compare(password, r.rows[0].password_hash))
    return res.status(401).json({ error: 'Usuario o contraseña incorrectos' });
  const u = r.rows[0];
  const token = jwt.sign({ id: u.id, nombre: u.nombre, rol: u.rol }, JWT_SECRET, { expiresIn: '30d' });
  res.json({ token, nombre: u.nombre, rol: u.rol });
});

// ─── USUARIOS ─────────────────────────────────────────────────────────────────
app.get('/api/usuarios', auth, adminOnly, async (req, res) => {
  const r = await pool.query('SELECT id,nombre,usuario,rol,creado_en FROM ct_usuarios ORDER BY id');
  res.json(r.rows);
});
app.post('/api/usuarios', auth, adminOnly, async (req, res) => {
  const { nombre, usuario, password, rol } = req.body;
  try {
    const hash = await bcrypt.hash(password, 10);
    await pool.query('INSERT INTO ct_usuarios (nombre,usuario,password_hash,rol) VALUES ($1,$2,$3,$4)', [nombre,usuario,hash,rol||'operativo']);
    res.json({ ok: true });
  } catch(e) {
    if (e.code==='23505') return res.status(400).json({ error: 'Usuario ya existe' });
    throw e;
  }
});
app.delete('/api/usuarios/:id', auth, adminOnly, async (req, res) => {
  if (parseInt(req.params.id)===req.user.id) return res.status(400).json({ error: 'No puedes eliminarte' });
  await pool.query('DELETE FROM ct_usuarios WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});
app.put('/api/usuarios/:id/password', auth, adminOnly, async (req, res) => {
  const hash = await bcrypt.hash(req.body.password, 10);
  await pool.query('UPDATE ct_usuarios SET password_hash=$1 WHERE id=$2', [hash, req.params.id]);
  res.json({ ok: true });
});

// ─── CAFE VERDE ───────────────────────────────────────────────────────────────
app.get('/api/verde', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM ct_cafe_verde WHERE activo=TRUE ORDER BY creado_en DESC');
  res.json(r.rows);
});
app.post('/api/verde', auth, async (req, res) => {
  const { origen,variedad,proceso,proveedor,stock_kg,precio_kg,fecha_compra,notas } = req.body;
  const r = await pool.query(
    'INSERT INTO ct_cafe_verde (origen,variedad,proceso,proveedor,stock_kg,precio_kg,fecha_compra,notas) VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING *',
    [origen,variedad,proceso,proveedor,stock_kg||0,precio_kg||0,fecha_compra||null,notas]
  );
  res.json(r.rows[0]);
});
app.put('/api/verde/:id', auth, async (req, res) => {
  const { origen,variedad,proceso,proveedor,stock_kg,precio_kg,fecha_compra,notas } = req.body;
  const r = await pool.query(
    'UPDATE ct_cafe_verde SET origen=$1,variedad=$2,proceso=$3,proveedor=$4,stock_kg=$5,precio_kg=$6,fecha_compra=$7,notas=$8 WHERE id=$9 RETURNING *',
    [origen,variedad,proceso,proveedor,stock_kg,precio_kg,fecha_compra||null,notas,req.params.id]
  );
  res.json(r.rows[0]);
});
app.delete('/api/verde/:id', auth, async (req, res) => {
  await pool.query('UPDATE ct_cafe_verde SET activo=FALSE WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// ─── LOTES ────────────────────────────────────────────────────────────────────
app.get('/api/lotes', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM ct_lotes ORDER BY fecha_tueste DESC, creado_en DESC');
  res.json(r.rows);
});
app.post('/api/lotes', auth, async (req, res) => {
  const { codigo,cafe_verde_id,origen_nombre,peso_verde,peso_tostado,perfil,fecha_tueste,dias_reposo,fecha_lista,destino,cliente,notas_cata,score_sca,estado,fuente } = req.body;
  // Descontar del inventario verde
  if (cafe_verde_id && peso_verde) {
    await pool.query('UPDATE ct_cafe_verde SET stock_kg=stock_kg-$1 WHERE id=$2', [peso_verde, cafe_verde_id]);
  }
  const r = await pool.query(
    `INSERT INTO ct_lotes (codigo,cafe_verde_id,origen_nombre,peso_verde,peso_tostado,perfil,fecha_tueste,dias_reposo,fecha_lista,destino,cliente,notas_cata,score_sca,estado,fuente)
     VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15) RETURNING *`,
    [codigo,cafe_verde_id||null,origen_nombre,peso_verde||0,peso_tostado||0,perfil,fecha_tueste,dias_reposo||7,fecha_lista||null,destino,cliente,notas_cata,score_sca||null,estado||'reposo',fuente||'manual']
  );
  res.json(r.rows[0]);
});
app.put('/api/lotes/:id', auth, async (req, res) => {
  const { codigo,origen_nombre,peso_verde,peso_tostado,perfil,fecha_tueste,dias_reposo,fecha_lista,destino,cliente,notas_cata,score_sca,estado } = req.body;
  const r = await pool.query(
    `UPDATE ct_lotes SET codigo=$1,origen_nombre=$2,peso_verde=$3,peso_tostado=$4,perfil=$5,fecha_tueste=$6,dias_reposo=$7,fecha_lista=$8,destino=$9,cliente=$10,notas_cata=$11,score_sca=$12,estado=$13 WHERE id=$14 RETURNING *`,
    [codigo,origen_nombre,peso_verde,peso_tostado,perfil,fecha_tueste,dias_reposo,fecha_lista||null,destino,cliente,notas_cata,score_sca||null,estado,req.params.id]
  );
  res.json(r.rows[0]);
});
app.delete('/api/lotes/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM ct_lotes WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// Importar CSV de Cropster
app.post('/api/lotes/importar-csv', auth, upload.single('file'), async (req, res) => {
  try {
    const text = req.file.buffer.toString('utf8');
    const lines = text.split('\n').filter(l => l.trim());
    const headers = lines[0].split(',').map(h => h.trim().toLowerCase().replace(/"/g,''));
    const lotes = [];
    for (let i = 1; i < lines.length; i++) {
      const vals = lines[i].split(',').map(v => v.trim().replace(/"/g,''));
      const row = {};
      headers.forEach((h, idx) => row[h] = vals[idx] || '');
      // Mapeo flexible de columnas Cropster
      const fecha = row['date'] || row['fecha'] || row['roast date'] || '';
      const origen = row['green coffee'] || row['green'] || row['origen'] || row['coffee'] || '';
      const verdeKg = parseFloat(row['green weight'] || row['verde'] || row['batch weight'] || 0);
      const tostadoKg = parseFloat(row['roasted weight'] || row['tostado'] || row['end weight'] || 0);
      const perfil = row['profile'] || row['perfil'] || 'Medio';
      if (!fecha && !origen) continue;
      const fl = fecha ? new Date(fecha) : new Date();
      fl.setDate(fl.getDate() + 7);
      const r = await pool.query(
        `INSERT INTO ct_lotes (origen_nombre,peso_verde,peso_tostado,perfil,fecha_tueste,dias_reposo,fecha_lista,estado,fuente)
         VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9) RETURNING *`,
        [origen,verdeKg,tostadoKg,perfil,fecha||new Date().toISOString().split('T')[0],7,fl.toISOString().split('T')[0],'reposo','cropster']
      );
      lotes.push(r.rows[0]);
    }
    res.json({ importados: lotes.length, lotes });
  } catch(e) {
    res.status(400).json({ error: 'Error al procesar CSV: ' + e.message });
  }
});

// ─── DASHBOARD ────────────────────────────────────────────────────────────────
app.get('/api/dashboard', auth, async (req, res) => {
  const [lotes, verde, pedidos, cobros] = await Promise.all([
    pool.query('SELECT * FROM ct_lotes'),
    pool.query('SELECT * FROM ct_cafe_verde WHERE activo=TRUE'),
    pool.query('SELECT * FROM ct_pedidos'),
    pool.query('SELECT * FROM ct_cobros')
  ]);
  const hoy = new Date(); hoy.setHours(12,0,0,0);
  const lotesData = lotes.rows;
  const pedidosData = pedidos.rows;
  const cobrosData = cobros.rows;
  const totalCobrado = cobrosData.reduce((a,c)=>a+parseFloat(c.pagado||0),0);
  const totalDeuda = cobrosData.reduce((a,c)=>a+(parseFloat(c.total||0)-parseFloat(c.pagado||0)),0);
  res.json({
    lotes_totales: lotesData.length,
    kg_tostados_mes: lotesData.filter(l=>{const d=new Date(l.fecha_tueste);return d.getMonth()===hoy.getMonth()&&d.getFullYear()===hoy.getFullYear();}).reduce((a,l)=>a+parseFloat(l.peso_tostado||0),0),
    lotes_reposo: lotesData.filter(l=>l.estado!=='entregado'&&new Date(l.fecha_lista)>hoy).length,
    lotes_listos: lotesData.filter(l=>l.estado!=='entregado'&&new Date(l.fecha_lista)<=hoy).length,
    stock_verde_kg: verde.rows.reduce((a,v)=>a+parseFloat(v.stock_kg||0),0),
    pedidos_pendientes: pedidosData.filter(p=>p.estado!=='entregado').length,
    por_cobrar: totalDeuda,
    cobrado_mes: totalCobrado
  });
});

// ─── CLIENTES ─────────────────────────────────────────────────────────────────
app.get('/api/clientes', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM ct_clientes ORDER BY nombre');
  res.json(r.rows);
});
app.post('/api/clientes', auth, async (req, res) => {
  const { nombre,tipo,telefono,email,direccion,notas } = req.body;
  const r = await pool.query('INSERT INTO ct_clientes (nombre,tipo,telefono,email,direccion,notas) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [nombre,tipo||'b2b',telefono,email,direccion,notas]);
  res.json(r.rows[0]);
});
app.delete('/api/clientes/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM ct_clientes WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// ─── PRODUCTOS ────────────────────────────────────────────────────────────────
app.get('/api/productos', auth, async (req, res) => {
  await pool.query('ALTER TABLE ct_productos ADD COLUMN IF NOT EXISTS tipo_tueste VARCHAR(50)');
  const r = await pool.query('SELECT * FROM ct_productos WHERE activo=TRUE ORDER BY nombre');
  res.json(r.rows);
});
app.put('/api/productos/:id', auth, async (req, res) => {
  const { nombre, presentacion, peso_g, precio, tipo_tueste } = req.body;
  const r = await pool.query(
    'UPDATE ct_productos SET nombre=$1,presentacion=$2,peso_g=$3,precio=$4,tipo_tueste=$5 WHERE id=$6 RETURNING *',
    [nombre, presentacion, peso_g||null, precio||0, tipo_tueste||null, req.params.id]
  );
  res.json(r.rows[0]);
});
app.delete('/api/productos/:id', auth, async (req, res) => {
  await pool.query('UPDATE ct_productos SET activo=FALSE WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});
app.post('/api/productos', auth, async (req, res) => {
  const { nombre, presentacion, peso_g, precio, tipo_tueste } = req.body;
  const r = await pool.query(
    'INSERT INTO ct_productos (nombre,presentacion,peso_g,precio,tipo_tueste) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [nombre, presentacion||null, peso_g||null, precio||0, tipo_tueste||null]
  );
  res.json(r.rows[0]);
});

// ─── PEDIDOS ──────────────────────────────────────────────────────────────────
app.get('/api/pedidos', auth, async (req, res) => {
  await pool.query('ALTER TABLE ct_pedidos ADD COLUMN IF NOT EXISTS requiere_factura BOOLEAN DEFAULT FALSE');
  await pool.query('ALTER TABLE ct_pedidos ADD COLUMN IF NOT EXISTS rfc VARCHAR(20)');
  await pool.query('ALTER TABLE ct_pedidos ADD COLUMN IF NOT EXISTS razon_social VARCHAR(300)');
  await pool.query('ALTER TABLE ct_pedidos ADD COLUMN IF NOT EXISTS uso_cfdi VARCHAR(100)');
  await pool.query('ALTER TABLE ct_pedidos ADD COLUMN IF NOT EXISTS factura_emitida BOOLEAN DEFAULT FALSE');
  await pool.query('ALTER TABLE ct_clientes ADD COLUMN IF NOT EXISTS rfc VARCHAR(20)');
  await pool.query('ALTER TABLE ct_clientes ADD COLUMN IF NOT EXISTS razon_social VARCHAR(300)');
  const r = await pool.query(`
    SELECT p.*, json_agg(pi.*) as items
    FROM ct_pedidos p
    LEFT JOIN ct_pedido_items pi ON pi.pedido_id=p.id
    GROUP BY p.id ORDER BY p.creado_en DESC`);
  res.json(r.rows);
});
app.put('/api/pedidos/:id/factura', auth, async (req, res) => {
  const r = await pool.query(
    'UPDATE ct_pedidos SET factura_emitida=$1 WHERE id=$2 RETURNING *',
    [req.body.factura_emitida, req.params.id]
  );
  res.json(r.rows[0]);
});
app.post('/api/pedidos', auth, async (req, res) => {
  const { cliente_id,cliente_nombre,fecha_pedido,fecha_entrega,nota,items,requiere_factura,rfc,razon_social,uso_cfdi } = req.body;
  const total = (items||[]).reduce((a,i)=>a+parseFloat(i.subtotal||0),0);
  const r = await pool.query(
    'INSERT INTO ct_pedidos (cliente_id,cliente_nombre,fecha_pedido,fecha_entrega,total,nota,requiere_factura,rfc,razon_social,uso_cfdi) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10) RETURNING *',
    [cliente_id||null,cliente_nombre,fecha_pedido,fecha_entrega||null,total,nota,requiere_factura||false,rfc||null,razon_social||null,uso_cfdi||null]
  );
  const pedido = r.rows[0];
  for (const item of (items||[])) {
    await pool.query('INSERT INTO ct_pedido_items (pedido_id,descripcion,cantidad,unidad,precio_unitario,subtotal) VALUES ($1,$2,$3,$4,$5,$6)',
      [pedido.id,item.descripcion,item.cantidad,item.unidad,item.precio_unitario,item.subtotal]);
  }
  // Auto-crear cobro
  if (total > 0) {
    await pool.query('INSERT INTO ct_cobros (cliente_id,cliente_nombre,pedido_id,concepto,total,pagado,fecha) VALUES ($1,$2,$3,$4,$5,$6,$7)',
      [cliente_id||null,cliente_nombre,pedido.id,`Pedido #${pedido.id}`,total,0,fecha_pedido]);
  }
  res.json(pedido);
});
app.put('/api/pedidos/:id/estado', auth, async (req, res) => {
  const r = await pool.query('UPDATE ct_pedidos SET estado=$1 WHERE id=$2 RETURNING *', [req.body.estado, req.params.id]);
  res.json(r.rows[0]);
});
app.put('/api/pedidos/:id', auth, async (req, res) => {
  const { cliente_nombre, fecha_pedido, fecha_entrega, nota, total, items, requiere_factura, rfc, razon_social, uso_cfdi } = req.body;
  const r = await pool.query(
    'UPDATE ct_pedidos SET cliente_nombre=$1,fecha_pedido=$2,fecha_entrega=$3,nota=$4,total=$5,requiere_factura=$6,rfc=$7,razon_social=$8,uso_cfdi=$9 WHERE id=$10 RETURNING *',
    [cliente_nombre, fecha_pedido, fecha_entrega||null, nota, total||0, requiere_factura||false, rfc||null, razon_social||null, uso_cfdi||null, req.params.id]
  );
  if (items) {
    await pool.query('DELETE FROM ct_pedido_items WHERE pedido_id=$1', [req.params.id]);
    for (const it of items) {
      await pool.query(
        'INSERT INTO ct_pedido_items (pedido_id,descripcion,cantidad,unidad,precio_unitario,subtotal) VALUES ($1,$2,$3,$4,$5,$6)',
        [req.params.id, it.descripcion, it.cantidad, it.unidad||'pza', it.precio_unitario, it.subtotal]
      );
    }
  }
  res.json(r.rows[0]);
});
app.delete('/api/pedidos/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM ct_pedidos WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// ─── COBROS ───────────────────────────────────────────────────────────────────
app.get('/api/cobros', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM ct_cobros ORDER BY creado_en DESC');
  res.json(r.rows);
});
app.post('/api/cobros', auth, async (req, res) => {
  const { cliente_id,cliente_nombre,concepto,total,pagado,fecha,metodo } = req.body;
  const r = await pool.query('INSERT INTO ct_cobros (cliente_id,cliente_nombre,concepto,total,pagado,fecha,metodo) VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING *',
    [cliente_id||null,cliente_nombre,concepto,total||0,pagado||0,fecha,metodo]);
  res.json(r.rows[0]);
});
app.put('/api/cobros/:id', auth, async (req, res) => {
  const { pagado,metodo } = req.body;
  const r = await pool.query('UPDATE ct_cobros SET pagado=$1,metodo=$2 WHERE id=$3 RETURNING *', [pagado,metodo,req.params.id]);
  res.json(r.rows[0]);
});
app.delete('/api/cobros/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM ct_cobros WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

// ─── SUCURSALES ───────────────────────────────────────────────────────────────
app.get('/api/sucursales', auth, async (req, res) => {
  const r = await pool.query('SELECT * FROM ct_sucursales WHERE activo=TRUE ORDER BY id');
  res.json(r.rows);
});
app.post('/api/sucursales', auth, async (req, res) => {
  const { nombre, ciudad, direccion, contacto, telefono, notas } = req.body;
  const r = await pool.query(
    'INSERT INTO ct_sucursales (nombre,ciudad,direccion,contacto,telefono,notas) VALUES ($1,$2,$3,$4,$5,$6) RETURNING *',
    [nombre, ciudad||null, direccion||null, contacto||null, telefono||null, notas||null]
  );
  res.json(r.rows[0]);
});
app.put('/api/sucursales/:id', auth, async (req, res) => {
  const { nombre, ciudad, direccion, contacto, telefono, notas } = req.body;
  const r = await pool.query(
    'UPDATE ct_sucursales SET nombre=$1,ciudad=$2,direccion=$3,contacto=$4,telefono=$5,notas=$6 WHERE id=$7 RETURNING *',
    [nombre, ciudad||null, direccion||null, contacto||null, telefono||null, notas||null, req.params.id]
  );
  res.json(r.rows[0]);
});

// ─── ENTREGAS SUCURSAL ────────────────────────────────────────────────────────
app.get('/api/sucursales/:id/entregas', auth, async (req, res) => {
  const r = await pool.query(
    'SELECT * FROM ct_entregas_sucursal WHERE sucursal_id=$1 ORDER BY fecha ASC',
    [req.params.id]
  );
  res.json(r.rows);
});
app.post('/api/sucursales/:id/entregas', auth, async (req, res) => {
  const { fecha, productos, kg_total, notas } = req.body;
  const r = await pool.query(
    'INSERT INTO ct_entregas_sucursal (sucursal_id,fecha,productos,kg_total,notas) VALUES ($1,$2,$3,$4,$5) RETURNING *',
    [req.params.id, fecha, productos||null, kg_total||null, notas||null]
  );
  res.json(r.rows[0]);
});
app.put('/api/entregas-sucursal/:id', auth, async (req, res) => {
  const { fecha, productos, kg_total, estado, notas } = req.body;
  const r = await pool.query(
    'UPDATE ct_entregas_sucursal SET fecha=$1,productos=$2,kg_total=$3,estado=$4,notas=$5 WHERE id=$6 RETURNING *',
    [fecha, productos||null, kg_total||null, estado||'programada', notas||null, req.params.id]
  );
  res.json(r.rows[0]);
});
app.delete('/api/entregas-sucursal/:id', auth, async (req, res) => {
  await pool.query('DELETE FROM ct_entregas_sucursal WHERE id=$1', [req.params.id]);
  res.json({ ok: true });
});

app.use((err,req,res,next) => { console.error(err); res.status(500).json({ error: 'Error interno' }); });

initDB().then(() => app.listen(PORT, () => console.log(`Puerto ${PORT}`))).catch(e => { console.error(e); process.exit(1); });
