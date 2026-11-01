// Bloqueo por intentos para usuarios que NO existen. Para los que existen lo hace la BD
// (registrar_intento_login + usuario.bloqueado_hasta). Ambos siguen la misma regla
// (N fallos -> bloqueo de S segundos) para que desde fuera no se pueda distinguir
// una cuenta real de una inexistente.
const mapa = new Map();   // usuario -> { fallos, hasta, ts }

function estado(u) {
  const e = mapa.get(u);
  return e && e.hasta > Date.now() ? e.hasta : null;
}
function fallo(u, max, segundos) {
  const e = mapa.get(u) || { fallos: 0, hasta: 0, ts: 0 };
  if (e.hasta > Date.now()) return e.hasta;
  e.fallos += 1; e.ts = Date.now();
  if (e.fallos >= max) { e.fallos = 0; e.hasta = Date.now() + segundos * 1000; }
  mapa.set(u, e);
  if (mapa.size > 20000) limpiar(true);
  return e.hasta > Date.now() ? e.hasta : null;
}
function limpiar(forzar = false) {
  const ahora = Date.now();
  for (const [k, e] of mapa) if (forzar ? e.hasta < ahora : e.hasta < ahora && ahora - e.ts > 15 * 60 * 1000) mapa.delete(k);
}
setInterval(limpiar, 60000).unref();

module.exports = { estado, fallo };
