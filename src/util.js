// Utilidades comunes
class HttpError extends Error {
  constructor(status, mensaje, codigo) { super(mensaje); this.status = status; this.codigo = codigo; }
}
// Express 4 no captura errores de funciones async: este envoltorio los pasa al manejador central
const wrap = (fn) => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
module.exports = { HttpError, wrap };
