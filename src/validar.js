// Validación de entradas (nunca se confía en lo que envía el navegador)
const { HttpError } = require('./util');
const bad = (m) => new HttpError(422, m);

const texto = (v, nombre, { min = 1, max = 200, opcional = false } = {}) => {
  if (v === undefined || v === null || v === '') { if (opcional) return null; throw bad(`${nombre} es obligatorio`); }
  if (typeof v !== 'string') throw bad(`${nombre} no es válido`);
  const t = v.trim();
  if (t.length < min || t.length > max) throw bad(`${nombre} debe tener entre ${min} y ${max} caracteres`);
  return t;
};
const fecha = (v, nombre, opcional = false) => {
  if (!v && opcional) return null;
  if (typeof v !== 'string' || !/^\d{4}-\d{2}-\d{2}$/.test(v) || Number.isNaN(Date.parse(v + 'T00:00:00Z'))) throw bad(`${nombre} no es una fecha válida (AAAA-MM-DD)`);
  return v;
};
const enumerado = (v, nombre, valores) => { if (!valores.includes(v)) throw bad(`${nombre} no es válido`); return v; };
const entero = (v, nombre) => { const n = Number(v); if (!Number.isInteger(n) || n <= 0) throw bad(`${nombre} no es válido`); return n; };

module.exports = { texto, fecha, enumerado, entero, bad };
