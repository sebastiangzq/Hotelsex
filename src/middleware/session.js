// Identidad autenticada de cada petición (Parte 3a)
const config = require('../config');
const sessions = require('../auth/sessions');
const audit = require('../audit');
const { ROL_BD } = require('../db');
const { wrap } = require('../util');

const opcionesCookie = () => ({
  httpOnly: true,                  // JavaScript del navegador no puede leerla (mitiga XSS)
  sameSite: 'strict',              // no se envía desde otros sitios (mitiga CSRF)
  secure: config.cookieSecure,     // solo por HTTPS en producción
  path: '/',
});

function requireSession({ permitirCambioPassword = false } = {}) {
  return wrap(async (req, res, next) => {
    const token = req.cookies?.[config.cookieNombre];
    if (typeof token !== 'string' || token.length < 20 || token.length > 100) {
      return res.status(401).json({ error: 'Sesión inválida o expirada', codigo: 'NO_SESION' });
    }
    const s = await sessions.buscar(token);
    if (!s) {
      res.clearCookie(config.cookieNombre, opcionesCookie());
      return res.status(401).json({ error: 'Sesión inválida o expirada', codigo: 'NO_SESION' });
    }
    req.user = {
      id: s.id, codigo: s.codigo, username: s.username, nombre: s.nombre, rol: s.rol,
      dbRole: ROL_BD[s.rol], sesionId: s.sesion_id, mfaHabilitado: s.mfa_habilitado,
      debeCambiarPassword: s.debe_cambiar_password,
    };
    // Atajo para dejar constancia en la bitácora en nombre del usuario autenticado
    req.audit = (tipo, resultado, detalle) => audit.registrar({
      tipo, resultado, actorId: s.id, actorNombre: s.username, ip: req.ip, detalle });
    if (s.debe_cambiar_password && !permitirCambioPassword) {
      return res.status(403).json({ error: 'Debe cambiar su contraseña antes de continuar', codigo: 'CAMBIO_PASSWORD_REQUERIDO' });
    }
    next();
  });
}

module.exports = { requireSession, opcionesCookie };
