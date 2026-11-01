// Parte 2e · Segundo factor TOTP (RFC 6238: Google Authenticator, Authy, Microsoft Authenticator...)
const { authenticator } = require('otplib');
const config = require('../config');

authenticator.options = { digits: 6, step: 30, window: 1 };   // tolera ±30 s de desfase de reloj
const ultimoPaso = new Map();   // usuario -> último intervalo aceptado (evita reutilizar un código)

const nuevoSecreto = () => authenticator.generateSecret(20);
const uri = (usuario, secreto) => authenticator.keyuri(usuario, config.totpEmisor, secreto);

function verificar(usuarioId, secreto, codigo) {
  if (typeof codigo !== 'string' || !/^\d{6}$/.test(codigo)) return false;
  const delta = authenticator.checkDelta(codigo, secreto);
  if (delta === null || delta === undefined) return false;
  const paso = Math.floor(Date.now() / 30000) + delta;
  if ((ultimoPaso.get(usuarioId) || 0) >= paso) return false;     // código ya usado
  ultimoPaso.set(usuarioId, paso);
  return true;
}

// Limitador de intentos de 2FA por sesión: 3 fallos -> 60 s de pausa
const intentos = new Map();   // sesionId -> { fallos, hasta }
const bloqueada = (sid) => { const e = intentos.get(sid); return e && e.hasta > Date.now() ? Math.ceil((e.hasta - Date.now()) / 1000) : 0; };
function registrarFallo(sid) {
  const e = intentos.get(sid) || { fallos: 0, hasta: 0 };
  e.fallos += 1;
  if (e.fallos >= 3) { e.fallos = 0; e.hasta = Date.now() + 60000; }
  intentos.set(sid, e);
  return e.hasta > Date.now();
}
const limpiarIntentos = (sid) => intentos.delete(sid);
setInterval(() => { for (const [k, e] of intentos) if (e.hasta < Date.now() && !e.fallos) intentos.delete(k); }, 300000).unref();

module.exports = { nuevoSecreto, uri, verificar, bloqueada, registrarFallo, limpiarIntentos };
