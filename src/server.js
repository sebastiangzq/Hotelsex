const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const express = require('express');
const helmet = require('helmet');
const cookieParser = require('cookie-parser');
const rateLimit = require('express-rate-limit');
const config = require('./config');
const { pool, withRole, AUTH } = require('./db');
const { csrf, sinCache } = require('./middleware/security');

const app = express();
app.disable('x-powered-by');
if (config.trustProxy) app.set('trust proxy', config.trustProxy);

// Cabeceras de seguridad. CSP estricta: solo recursos propios (el frontend se sirve sin CDN ni scripts en línea)
app.use(helmet({
  contentSecurityPolicy: {
    useDefaults: false,
    directives: {
      defaultSrc: ["'self'"], scriptSrc: ["'self'"], styleSrc: ["'self'"],
      imgSrc: ["'self'", 'data:'], connectSrc: ["'self'"], objectSrc: ["'none'"],
      baseUri: ["'none'"], frameAncestors: ["'none'"], formAction: ["'self'"],
    },
  },
  referrerPolicy: { policy: 'no-referrer' },
}));
app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

// ------------------------------------------------------------------ API
app.get('/api/salud', (req, res) => res.json({ ok: true }));
app.use('/api', sinCache, csrf, rateLimit({ windowMs: 60 * 1000, limit: 300, standardHeaders: true, legacyHeaders: false, message: { error: 'Demasiadas solicitudes' } }));

// Cada archivo de src/routes se monta solo en /api/<nombre>  (auth.js -> /api/auth)
const dirRutas = path.join(__dirname, 'routes');
for (const f of fs.readdirSync(dirRutas).filter((x) => x.endsWith('.js')).sort()) {
  app.use('/api/' + path.basename(f, '.js'), require(path.join(dirRutas, f)));
}
app.use('/api', (req, res) => res.status(404).json({ error: 'No encontrado' }));

// ------------------------------------------------------------------ Frontend estático
app.use(express.static(path.join(__dirname, '..', 'public'), { index: 'index.html', maxAge: 0 }));

// ------------------------------------------------------------------ Manejo central de errores
// Al cliente nunca se le envían trazas ni nombres de tablas; el detalle queda en el log del servidor.
app.use((err, req, res, next) => {   // eslint-disable-line no-unused-vars
  if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'JSON inválido' });
  if (err.status && err.status < 500) return res.status(err.status).json({ error: err.message, codigo: err.codigo });
  const m = String(err.message || '');
  const permisoBD = m.startsWith('permission denied');
  switch (err.code) {
    case '23505': return res.status(409).json({ error: 'Ya existe un registro con esos datos' });
    case '23P01': return res.status(409).json({ error: 'La habitación ya tiene una estancia en esas fechas' });
    case '23503': return res.status(409).json({ error: 'Referencia no válida' });
    case '23514': case '22P02': case '22007': case '22008': return res.status(422).json({ error: 'Datos no válidos' });
    case '42501': case '23000': case 'P0001':
      if (!permisoBD) return res.status(err.code === '42501' ? 403 : 409).json({ error: m });   // mensajes escritos por los triggers del esquema
      console.error('[bd] privilegio denegado:', m, '·', req.method, req.originalUrl);
      return res.status(403).json({ error: 'Operación no permitida' });
    default: {
      const id = crypto.randomBytes(4).toString('hex');
      console.error(`[error ${id}]`, req.method, req.originalUrl, err);
      return res.status(500).json({ error: 'Error interno del servidor', id });
    }
  }
});

// ------------------------------------------------------------------ Arranque
async function verificarBD() {
  const r = await pool.query('SELECT current_user AS u, (SELECT rolsuper FROM pg_roles WHERE rolname = current_user) AS su');
  if (r.rows[0].su) {
    const msg = 'La aplicación se conecta como SUPERUSUARIO: los permisos por rol de la BD no sirven de nada.';
    if (config.env === 'production') throw new Error(msg);
    console.warn('[AVISO] ' + msg);
  }
  await withRole(AUTH, null, (c) => c.query('SELECT 1 FROM usuario LIMIT 1'));   // comprueba roles y grants de db/02_roles_app.sql
}

if (require.main === module) {
  verificarBD().then(() => {
    const srv = app.listen(config.port, () => console.log(`HotelSec escuchando en http://localhost:${config.port}`));
    const cerrar = () => srv.close(() => pool.end().then(() => process.exit(0)));
    process.on('SIGTERM', cerrar); process.on('SIGINT', cerrar);
  }).catch((e) => { console.error('[arranque] No se pudo preparar la base de datos:', e.message, '\n¿Ejecutó "npm run setup:db"?'); process.exit(1); });
}

module.exports = { app, verificarBD };
