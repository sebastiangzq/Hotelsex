const config = require('../config');

/** Defensa CSRF en dos capas, además de la cookie SameSite=Strict:
 *  1) si el navegador envía Origin, debe ser el de la propia app;
 *  2) toda petición que modifica datos debe llevar la cabecera X-Requested-With,
 *     que un sitio externo no puede enviar sin que el navegador pida permiso (CORS). */
function csrf(req, res, next) {
  if (['GET', 'HEAD', 'OPTIONS'].includes(req.method)) return next();
  const origen = req.get('origin');
  if (origen) {
    const permitido = config.appOrigin || `${req.protocol}://${req.get('host')}`;
    if (origen !== permitido) return res.status(403).json({ error: 'Origen no permitido' });
  }
  if (req.get('x-requested-with') !== 'hotelsec') return res.status(403).json({ error: 'Solicitud no válida' });
  next();
}

const sinCache = (req, res, next) => { res.set('Cache-Control', 'no-store'); next(); };

module.exports = { csrf, sinCache };
