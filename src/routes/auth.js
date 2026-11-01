// Partes 1 y 2 · Login, sesión, cambio de contraseña y segundo factor (TOTP)
const express = require('express');
const rateLimit = require('express-rate-limit');
const QRCode = require('qrcode');
const config = require('../config');
const { withRole, leerConfig, AUTH } = require('../db');
const { wrap } = require('../util');
const { cifrar, descifrar } = require('../crypto');
const pw = require('../auth/password');
const lockout = require('../auth/lockout');
const totp = require('../auth/totp');
const sessions = require('../auth/sessions');
const audit = require('../audit');
const { requireSession, opcionesCookie } = require('../middleware/session');

const router = express.Router();
const GENERICO = 'Credenciales incorrectas';   // Parte 2f: mismo mensaje exista o no la cuenta
const ms = (x) => (x ? new Date(x).getTime() : 0);

const limitadorLogin = rateLimit({
  windowMs: 15 * 60 * 1000, limit: config.loginRateMax, standardHeaders: true, legacyHeaders: false,
  message: { error: 'Demasiadas solicitudes. Intente más tarde.' },
});

// ---------------------------------------------------------------- LOGIN
router.post('/login', limitadorLogin, wrap(async (req, res) => {
  const { username, password } = req.body || {};
  if (typeof username !== 'string' || typeof password !== 'string' || !username.trim() || !password
      || username.length > 64 || password.length > 256) {
    return res.status(401).json({ error: GENERICO });
  }
  const uname = username.trim().toLowerCase();
  const ip = req.ip || null;

  const { cfg, fallosIp, user } = await withRole(AUTH, null, async (c) => {
    const cfg = await leerConfig(c);
    const f = ip ? await c.query(
      `SELECT count(*)::int AS n FROM intento_autenticacion
        WHERE ip_origen = $1::inet AND NOT exitoso AND ocurrido_en > now() - interval '15 minutes'`, [ip]) : { rows: [{ n: 0 }] };
    const u = await c.query(
      `SELECT u.id, u.username, u.nombre_completo AS nombre, u.codigo, u.estado, u.password_hash, u.bloqueado_hasta,
              u.debe_cambiar_password, u.mfa_habilitado, r.nombre AS rol
         FROM usuario u JOIN rol r ON r.id = u.rol_id WHERE lower(u.username) = $1`, [uname]);
    return { cfg, fallosIp: f.rows[0].n, user: u.rows[0] };
  });
  const max = parseInt(cfg.max_intentos_login, 10) || 3;
  const segundos = parseInt(cfg.bloqueo_segundos, 10) || 30;

  // Control por IP (además del control por cuenta)
  if (fallosIp >= config.maxFallosPorIp) {
    await audit.registrar({ tipo: 'autenticacion', resultado: 'fallo', actorNombre: uname, ip, detalle: 'Intento rechazado: demasiados fallos desde esta IP' });
    return res.status(429).json({ error: 'Demasiados intentos desde su red. Intente más tarde.' });
  }
  // Bloqueo temporal vigente: ni siquiera se verifica la contraseña
  const hasta = user ? ms(user.bloqueado_hasta) : lockout.estado(uname) || 0;
  if (hasta > Date.now()) {
    await audit.registrar({ tipo: 'autenticacion', resultado: 'fallo', actorId: user?.id, actorNombre: uname, ip, detalle: 'Intento durante bloqueo temporal' });
    return res.status(429).json({ error: 'Acceso bloqueado temporalmente por intentos fallidos', reintentar_en_s: Math.ceil((hasta - Date.now()) / 1000) });
  }

  // Verificación de credenciales (siempre se ejecuta Argon2, exista o no el usuario)
  const okPassword = await pw.verificar(user ? user.password_hash : await pw.hashSenuelo(), password);
  const ok = !!user && okPassword && user.estado === 'activa';

  if (!ok) {
    // La BD registra el motivo real (usuario inexistente / cuenta suspendida / clave mala), el cliente solo ve el genérico
    await withRole(AUTH, null, (c) => c.query('SELECT registrar_intento_login($1, $2::inet, false, NULL)', [uname, ip]));
    let nuevoHasta;
    if (user) {
      const r = await withRole(AUTH, null, (c) => c.query('SELECT bloqueado_hasta FROM usuario WHERE id = $1', [user.id]));
      nuevoHasta = ms(r.rows[0].bloqueado_hasta);
    } else {
      nuevoHasta = lockout.fallo(uname, max, segundos) || 0;
    }
    if (nuevoHasta > Date.now()) {
      return res.status(429).json({ error: 'Acceso bloqueado temporalmente por intentos fallidos', reintentar_en_s: Math.ceil((nuevoHasta - Date.now()) / 1000) });
    }
    return res.status(401).json({ error: GENERICO });
  }

  const token = await withRole(AUTH, user.id, async (c) => {
    await c.query('SELECT registrar_intento_login($1, $2::inet, true, NULL)', [uname, ip]);   // resetea contador de fallos
    return sessions.crear(c, { usuarioId: user.id, ip, userAgent: req.get('user-agent'), minutos: parseInt(cfg.sesion_duracion_minutos, 10) || 30 });
  });
  res.cookie(config.cookieNombre, token, { ...opcionesCookie(), maxAge: config.sesionAbsolutaHoras * 3600 * 1000 });
  res.json({
    usuario: { id: user.id, codigo: user.codigo, username: user.username, nombre: user.nombre, rol: user.rol },
    debe_cambiar_password: user.debe_cambiar_password,
    mfa_habilitado: user.mfa_habilitado,
  });
}));

// ---------------------------------------------------------------- LOGOUT
router.post('/logout', requireSession({ permitirCambioPassword: true }), wrap(async (req, res) => {
  await sessions.revocar(req.user.sesionId, 'Cierre de sesión del usuario');
  await req.audit('autenticacion', 'exito', 'Cierre de sesión');
  res.clearCookie(config.cookieNombre, opcionesCookie());
  res.json({ ok: true });
}));

// ---------------------------------------------------------------- ESTADO DE LA SESIÓN
router.get('/yo', requireSession({ permitirCambioPassword: true }), wrap(async (req, res) => {
  const u = req.user;
  const d = await withRole(AUTH, null, async (c) => {
    const cfg = await leerConfig(c);
    const p = await c.query(
      `SELECT rc.nombre AS recurso, op.nombre AS operacion
         FROM rol_permiso rp JOIN rol r ON r.id = rp.rol_id JOIN permiso pe ON pe.id = rp.permiso_id
         JOIN recurso rc ON rc.id = pe.recurso_id JOIN operacion op ON op.id = pe.operacion_id
        WHERE r.nombre = $1 AND rp.vigente_desde <= now() AND (rp.vigente_hasta IS NULL OR rp.vigente_hasta > now())
        ORDER BY rc.id, op.id`, [u.rol]);
    const m = await c.query(
      `SELECT mfa_verificado_en + make_interval(mins => $2::int) AS vigente_hasta
         FROM sesion WHERE id = $1 AND mfa_verificado_en > now() - make_interval(mins => $2::int)`,
      [u.sesionId, parseInt(cfg.mfa_vigencia_minutos, 10) || 5]);
    return { cfg, permisos: p.rows, mfaHasta: m.rows[0]?.vigente_hasta || null };
  });
  const permisos = {};
  for (const r of d.permisos) (permisos[r.recurso] ||= []).push(r.operacion);
  res.json({
    usuario: { id: u.id, codigo: u.codigo, username: u.username, nombre: u.nombre, rol: u.rol },
    debe_cambiar_password: u.debeCambiarPassword,
    mfa: { habilitado: u.mfaHabilitado, vigente_hasta: d.mfaHasta },
    permisos,
    modo_degradacion: d.cfg.modo_degradacion_segura === 'true',
    politica_password: { min_longitud: parseInt(d.cfg.password_min_longitud, 10) || 12 },
  });
}));

// ---------------------------------------------------------------- CAMBIO DE CONTRASEÑA
router.post('/cambiar-password', requireSession({ permitirCambioPassword: true }), wrap(async (req, res) => {
  const { actual, nueva } = req.body || {};
  if (typeof actual !== 'string' || typeof nueva !== 'string') return res.status(400).json({ error: 'Datos incompletos' });
  const u = req.user;
  const fila = await withRole(AUTH, null, async (c) => ({
    hash: (await c.query('SELECT password_hash FROM usuario WHERE id = $1', [u.id])).rows[0].password_hash,
    cfg: await leerConfig(c),
  }));
  if (!(await pw.verificar(fila.hash, actual))) {
    await withRole(AUTH, null, (c) => c.query('SELECT registrar_intento_login($1, $2::inet, false, $3)',
      [u.username, req.ip || null, 'Contraseña actual incorrecta al cambiar la contraseña']));
    return res.status(401).json({ error: 'La contraseña actual es incorrecta' });
  }
  const problema = pw.validarPolitica(nueva, { minLongitud: parseInt(fila.cfg.password_min_longitud, 10) || 12, username: u.username });
  if (problema) return res.status(422).json({ error: problema });
  if (actual === nueva) return res.status(422).json({ error: 'La nueva contraseña debe ser distinta de la actual' });

  const nuevoHash = await pw.hash(nueva);
  await withRole(AUTH, u.id, async (c) => {
    await c.query(`UPDATE usuario SET password_hash = $2, password_cambiada_en = now(), debe_cambiar_password = false WHERE id = $1`, [u.id, nuevoHash]);
    await sessions.revocarOtras(c, u.id, u.sesionId, 'Cambio de contraseña');      // cierra las demás sesiones abiertas
    await audit.registrarEn(c, { tipo: 'identidad', resultado: 'exito', actorId: u.id, actorNombre: u.username, ip: req.ip, detalle: 'Contraseña cambiada por el propio usuario' });
  });
  res.json({ ok: true });
}));

// ---------------------------------------------------------------- SEGUNDO FACTOR (TOTP)
// 1) iniciar: pide la contraseña de nuevo (si no, una sesión robada podría registrar SU autenticador)
router.post('/2fa/iniciar', requireSession(), wrap(async (req, res) => {
  const { password } = req.body || {};
  const u = req.user;
  if (typeof password !== 'string') return res.status(400).json({ error: 'Datos incompletos' });
  const f = (await withRole(AUTH, null, (c) => c.query('SELECT password_hash, mfa_habilitado FROM usuario WHERE id = $1', [u.id]))).rows[0];
  if (f.mfa_habilitado) return res.status(409).json({ error: 'El segundo factor ya está habilitado' });
  if (!(await pw.verificar(f.password_hash, password))) {
    await req.audit('autenticacion', 'fallo', 'Contraseña incorrecta al iniciar la configuración del 2FA');
    return res.status(401).json({ error: 'Contraseña incorrecta' });
  }
  const secreto = totp.nuevoSecreto();
  await withRole(AUTH, u.id, async (c) => {
    await c.query('UPDATE usuario SET mfa_secreto_cifrado = $2 WHERE id = $1', [u.id, cifrar(secreto, 'mfa:' + u.id, 'mfa')]);   // queda pendiente (mfa_habilitado sigue en false)
    await audit.registrarEn(c, { tipo: 'autenticacion', resultado: 'solicitado', actorId: u.id, actorNombre: u.username, ip: req.ip, detalle: 'Configuración de 2FA iniciada' });
  });
  const uri = totp.uri(u.username, secreto);
  res.json({ secreto, uri, qr: await QRCode.toDataURL(uri, { margin: 1, width: 220 }) });
}));

// 2) activar: confirma con el primer código que el autenticador quedó bien configurado
router.post('/2fa/activar', requireSession(), wrap(async (req, res) => {
  const u = req.user;
  const f = (await withRole(AUTH, null, (c) => c.query('SELECT mfa_habilitado, mfa_secreto_cifrado FROM usuario WHERE id = $1', [u.id]))).rows[0];
  if (f.mfa_habilitado) return res.status(409).json({ error: 'El segundo factor ya está habilitado' });
  if (!f.mfa_secreto_cifrado) return res.status(409).json({ error: 'Inicie primero la configuración del 2FA' });
  const espera = totp.bloqueada(u.sesionId);
  if (espera) return res.status(429).json({ error: 'Demasiados códigos incorrectos', reintentar_en_s: espera });

  const secreto = descifrar(f.mfa_secreto_cifrado, 'mfa:' + u.id, 'mfa');
  if (!totp.verificar(u.id, secreto, (req.body || {}).codigo)) {
    totp.registrarFallo(u.sesionId);
    await req.audit('autenticacion', 'fallo', 'Código incorrecto al activar el 2FA');
    return res.status(401).json({ error: 'Código incorrecto' });
  }
  await withRole(AUTH, u.id, async (c) => {
    await c.query('UPDATE usuario SET mfa_habilitado = true WHERE id = $1', [u.id]);
    await c.query('UPDATE sesion SET mfa_verificado_en = now() WHERE id = $1', [u.sesionId]);
    await audit.registrarEn(c, { tipo: 'autenticacion', resultado: 'exito', actorId: u.id, actorNombre: u.username, ip: req.ip, detalle: 'Segundo factor (TOTP) habilitado' });
  });
  totp.limpiarIntentos(u.sesionId);
  res.json({ ok: true });
}));

// 3) verificar: paso adicional antes de una operación de alto riesgo (vale 'mfa_vigencia_minutos')
router.post('/2fa/verificar', requireSession(), wrap(async (req, res) => {
  const u = req.user;
  const f = (await withRole(AUTH, null, (c) => c.query('SELECT mfa_habilitado, mfa_secreto_cifrado FROM usuario WHERE id = $1', [u.id]))).rows[0];
  if (!f.mfa_habilitado) return res.status(409).json({ error: 'Debe configurar el segundo factor primero', codigo: 'MFA_NO_CONFIGURADO' });
  const espera = totp.bloqueada(u.sesionId);
  if (espera) return res.status(429).json({ error: 'Demasiados códigos incorrectos', reintentar_en_s: espera });

  const secreto = descifrar(f.mfa_secreto_cifrado, 'mfa:' + u.id, 'mfa');
  if (!totp.verificar(u.id, secreto, (req.body || {}).codigo)) {
    const bloqueado = totp.registrarFallo(u.sesionId);
    await req.audit('autenticacion', 'fallo', bloqueado ? 'Código 2FA incorrecto: verificación bloqueada 60 s' : 'Código 2FA incorrecto');
    return res.status(401).json({ error: 'Código incorrecto' });
  }
  await withRole(AUTH, u.id, async (c) => {
    await c.query('UPDATE sesion SET mfa_verificado_en = now() WHERE id = $1', [u.sesionId]);
    await audit.registrarEn(c, { tipo: 'autenticacion', resultado: 'exito', actorId: u.id, actorNombre: u.username, ip: req.ip, detalle: '2FA validado' });
  });
  totp.limpiarIntentos(u.sesionId);
  res.json({ ok: true });
}));

module.exports = router;
