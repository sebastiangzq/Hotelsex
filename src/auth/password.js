// Parte 2b · Contraseñas con Argon2id (mismos parámetros que el esquema: 64 MiB, t=3, p=4)
const argon2 = require('argon2');

const OPCIONES = { type: argon2.argon2id, memoryCost: 65536, timeCost: 3, parallelism: 4 };
const COMUNES = new Set(['password', 'contraseña', '123456789012', 'qwertyuiop12', 'hotelsec2026', 'admin2026admin']);

const hash = (pw) => argon2.hash(pw, OPCIONES);
async function verificar(hashGuardado, pw) {
  try { return await argon2.verify(hashGuardado, pw); } catch { return false; }
}
// Hash "señuelo": se verifica contra él cuando el usuario no existe, para que
// responder tarde lo mismo exista o no la cuenta (evita enumeración por tiempo).
let senuelo;
const hashSenuelo = async () => (senuelo ??= await hash('señuelo-no-es-una-cuenta-real'));

/** Devuelve null si cumple la política, o el texto del problema */
function validarPolitica(pw, { minLongitud = 12, username = '' } = {}) {
  if (typeof pw !== 'string') return 'Contraseña inválida';
  if (pw.length < minLongitud) return `La contraseña debe tener al menos ${minLongitud} caracteres`;
  if (pw.length > 128) return 'La contraseña no puede superar 128 caracteres';
  const clases = [/[a-z]/, /[A-Z]/, /\d/, /[^A-Za-z0-9]/].filter((r) => r.test(pw)).length;
  if (clases < 3) return 'Combine al menos 3 tipos: minúsculas, mayúsculas, números y símbolos';
  if (username && pw.toLowerCase().includes(username.toLowerCase())) return 'La contraseña no puede contener el nombre de usuario';
  if (COMUNES.has(pw.toLowerCase())) return 'Contraseña demasiado común';
  return null;
}

module.exports = { hash, verificar, hashSenuelo, validarPolitica };
