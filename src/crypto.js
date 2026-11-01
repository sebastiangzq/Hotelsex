// Protección de datos (Política 4): AES-256-GCM para datos personales y secretos 2FA,
// HMAC-SHA256 para buscar duplicados sin guardar el documento, SHA-256 para tokens de sesión.
// Las claves se DERIVAN (HKDF) de MASTER_KEY: una clave distinta por propósito.
const crypto = require('crypto');
const { master } = require('./config');

const salt = Buffer.from('hotelsec-v1');
const derivar = (info) => Buffer.from(crypto.hkdfSync('sha256', master, salt, info, 32));
const CLAVES = {
  datos: derivar('datos-personales'),
  hmac: derivar('hmac-documento'),
  mfa: derivar('secreto-totp'),
  export: derivar('exportacion-bitacora'),
};
const VERSION = 1;

/** Cifra texto. `aad` ata el cifrado a su contexto (p. ej. "huesped:telefono:<uuid>"):
 *  si alguien copia el bytea a otra fila/columna, el descifrado falla. */
function cifrar(texto, aad, clave = 'datos') {
  const buf = Buffer.isBuffer(texto) ? texto : Buffer.from(String(texto), 'utf8');
  const iv = crypto.randomBytes(12);
  const c = crypto.createCipheriv('aes-256-gcm', CLAVES[clave], iv);
  c.setAAD(Buffer.from(aad, 'utf8'));
  const ct = Buffer.concat([c.update(buf), c.final()]);
  return Buffer.concat([Buffer.from([VERSION]), iv, c.getAuthTag(), ct]);   // 1 + 12 + 16 + n
}

function descifrarBuffer(buf, aad, clave = 'datos') {
  if (!buf) return null;
  if (buf[0] !== VERSION) throw new Error('Versión de cifrado desconocida');
  const iv = buf.subarray(1, 13), tag = buf.subarray(13, 29), ct = buf.subarray(29);
  const d = crypto.createDecipheriv('aes-256-gcm', CLAVES[clave], iv);
  d.setAAD(Buffer.from(aad, 'utf8'));
  d.setAuthTag(tag);
  return Buffer.concat([d.update(ct), d.final()]);
}
const descifrar = (buf, aad, clave = 'datos') => (buf ? descifrarBuffer(buf, aad, clave).toString('utf8') : null);

/** HMAC del documento normalizado (mayúsculas, sin espacios/puntos/guiones) */
function hmacDocumento(doc) {
  const n = String(doc).normalize('NFKC').toUpperCase().replace(/[\s.\-]/g, '');
  return crypto.createHmac('sha256', CLAVES.hmac).update(n).digest();
}
const sha256 = (b) => crypto.createHash('sha256').update(b).digest();
const tokenAleatorio = () => crypto.randomBytes(32).toString('base64url');

/** Contraseña temporal aleatoria que cumple la política (16 caracteres) */
function passwordTemporal() {
  const g = { m: 'abcdefghijkmnopqrstuvwxyz', M: 'ABCDEFGHJKLMNPQRSTUVWXYZ', d: '23456789', s: '#$%&*+-=?@' };
  const todos = g.m + g.M + g.d + g.s;
  const pick = (s) => s[crypto.randomInt(s.length)];
  const chars = [pick(g.m), pick(g.M), pick(g.d), pick(g.s)];
  while (chars.length < 16) chars.push(pick(todos));
  for (let i = chars.length - 1; i > 0; i--) { const j = crypto.randomInt(i + 1); [chars[i], chars[j]] = [chars[j], chars[i]]; }
  return chars.join('');
}

module.exports = { cifrar, descifrar, descifrarBuffer, hmacDocumento, sha256, tokenAleatorio, passwordTemporal, CLAVES };
