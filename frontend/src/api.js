// Cliente de la API. Cookie de sesión httpOnly (el JS nunca la ve) + cabecera anti-CSRF.
export class ApiError extends Error {
  constructor(status, data) {
    super((data && data.error) || 'Error de comunicación con el servidor');
    this.status = status; this.codigo = data && data.codigo; this.data = data || {};
  }
}
let alExpirar = () => {};
export const onSesionExpirada = (fn) => { alExpirar = fn; };

async function pedir(metodo, url, cuerpo, binario) {
  let r;
  try {
    r = await fetch('/api' + url, {
      method: metodo, credentials: 'same-origin',
      headers: { 'X-Requested-With': 'hotelsec', ...(cuerpo !== undefined ? { 'Content-Type': 'application/json' } : {}) },
      body: cuerpo !== undefined ? JSON.stringify(cuerpo) : undefined,
    });
  } catch { throw new ApiError(0, { error: 'No hay conexión con el servidor' }); }
  if (r.ok && binario) return { blob: await r.blob(), huella: r.headers.get('X-Huella-SHA256'), nombre: (/filename="?([^"]+)"?/.exec(r.headers.get('Content-Disposition') || '') || [])[1] };
  let j = {};
  try { j = await r.json(); } catch { /* sin cuerpo */ }
  if (!r.ok) {
    if (r.status === 401 && j.codigo === 'NO_SESION') alExpirar();
    throw new ApiError(r.status, j);
  }
  return j;
}
export const api = {
  get: (u) => pedir('GET', u),
  post: (u, b = {}) => pedir('POST', u, b),
  put: (u, b = {}) => pedir('PUT', u, b),
  patch: (u, b = {}) => pedir('PATCH', u, b),
  descarga: (u) => pedir('GET', u, undefined, true),
};
