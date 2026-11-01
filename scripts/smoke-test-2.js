// Prueba del Paso 2 contra un servidor levantado y una BD RECIÉN creada (npm run setup:db -- --reset --yes).
//   node scripts/smoke-test-2.js      (para el respaldo necesita pg_dump y OWNER_DATABASE_URL)
require('dotenv').config();
const { authenticator } = require('otplib');
const { execSync } = require('child_process');
const { descifrar, sha256 } = require('../src/crypto');
const BASE = process.env.BASE || 'http://localhost:3000';
let ok = 0, mal = 0;
const check = (n, c, x = '') => { c ? ok++ : mal++; console.log((c ? '  ✔ ' : '  ✘ ') + n + (c ? '' : '   → ' + String(x).slice(0, 300))); };
const sec = (t) => console.log('\n' + t);

async function api(m, r, body, ck) {
  const res = await fetch(BASE + r, { method: m, headers: { 'Content-Type': 'application/json', 'X-Requested-With': 'hotelsec', ...(ck ? { Cookie: ck } : {}) }, body: body ? JSON.stringify(body) : undefined });
  const buf = Buffer.from(await res.arrayBuffer());
  let j = {}; try { j = JSON.parse(buf.toString()); } catch { /* binario */ }
  const set = res.headers.get('set-cookie');
  return { s: res.status, j, cookie: set ? set.split(';')[0] : null, buf, h: res.headers };
}
const login = async (u, p) => { const r = await api('POST', '/api/auth/login', { username: u, password: p }); return r.s === 200 ? { ck: r.cookie, j: r.j } : { err: r }; };
// código TOTP del intervalo siguiente (el actual ya lo consumió la activación; el servidor impide reutilizar un código)
const codigoSig = (s) => { authenticator.options = { epoch: Date.now() + 30000 }; const c = authenticator.generate(s); authenticator.resetOptions(); return c; };
const codigoAhora = (s) => { authenticator.resetOptions(); return authenticator.generate(s); };
async function enrolar(ck, pass) {
  const i = await api('POST', '/api/auth/2fa/iniciar', { password: pass }, ck);
  const a = await api('POST', '/api/auth/2fa/activar', { codigo: codigoAhora(i.j.secreto) }, ck);
  if (a.s !== 200) throw new Error('No se pudo activar 2FA: ' + JSON.stringify(a.j));
  return i.j.secreto;
}
const hoy = new Date().toISOString().slice(0, 10);
const mas = (d) => new Date(Date.now() + d * 864e5).toISOString().slice(0, 10);
const guest = (o) => ({ nombre: 'Carlos Mamani Quispe', documento_tipo: 'CI', documento: '6543210', nacionalidad: 'Boliviana', telefono: '+591 71234567', email: 'carlos@correo.bo',
  fecha_nacimiento: '1990-05-12', ingreso: hoy, salida: mas(3), habitacion: '104', metodo_pago: 'tarjeta', tarjeta_ultimos4: '4417', monto: 540, consentimiento: true, ...o });

(async () => {
  sec('0) Sesiones y 2FA de los actores');
  const A = await login('admin', 'Admin#2026'), R = await login('recepcion', 'Recep#2026'), U = await login('auditor', 'Audit#2026');
  check('login de admin, recepción y auditor', A.ck && R.ck && U.ck, JSON.stringify([A.err?.j, R.err?.j, U.err?.j]));
  const secAdmin = await enrolar(A.ck, 'Admin#2026');
  const secRec = await enrolar(R.ck, 'Recep#2026');
  const B = await login('admin', 'Admin#2026');                       // sesión NUEVA de admin, sin 2FA verificado
  const sinMfa = await api('POST', '/api/usuarios', { username: 'tester1', nombre: 'Tester Uno', rol: 'Recepcionista' }, B.ck);
  check('operación de alto riesgo sin 2FA vigente → MFA_REQUERIDO', sinMfa.s === 403 && sinMfa.j.codigo === 'MFA_REQUERIDO', JSON.stringify(sinMfa.j));
  const mfaOk = await api('POST', '/api/auth/2fa/verificar', { codigo: codigoSig(secAdmin) }, B.ck);
  check('verificar 2FA con un código válido', mfaOk.s === 200, JSON.stringify(mfaOk.j));
  const AD = B.ck;

  sec('1) Identidades y ciclo de vida');
  const lista = await api('GET', '/api/usuarios', null, AD);
  check('admin lista 5 identidades y no se filtra el UUID ni hashes', lista.s === 200 && lista.j.usuarios.length === 5 && !JSON.stringify(lista.j).includes('argon2') && !('id' in lista.j.usuarios[0]), JSON.stringify(lista.j).slice(0, 200));
  const denegado = await api('GET', '/api/usuarios', null, R.ck);
  check('recepcionista NO puede listar identidades → 403', denegado.s === 403 && denegado.j.codigo === 'DENEGADO');
  const nuevo = await api('POST', '/api/usuarios', { username: 'tester1', nombre: 'Tester Uno', rol: 'Recepcionista' }, AD);
  check('alta de identidad → suspendida + contraseña temporal aleatoria', nuevo.s === 201 && nuevo.j.estado === 'suspendida' && nuevo.j.password_temporal?.length === 16, JSON.stringify(nuevo.j));
  const t1 = nuevo.j.codigo, tmp1 = nuevo.j.password_temporal;
  check('usuario con formato inválido → 422', (await api('POST', '/api/usuarios', { username: 'No Valido!', nombre: 'X Y Z', rol: 'Auditor' }, AD)).s === 422);
  check('usuario repetido → 409', (await api('POST', '/api/usuarios', { username: 'tester1', nombre: 'Otro Nombre', rol: 'Auditor' }, AD)).s === 409);
  check('identidad suspendida no puede iniciar sesión (mismo 401 genérico)', (await login('tester1', tmp1)).err?.s === 401);
  const act = await api('POST', `/api/usuarios/${t1}/estado`, { estado: 'activa' }, AD);
  check('activar identidad', act.s === 200 && act.j.estado === 'activa', JSON.stringify(act.j));
  const T = await login('tester1', tmp1);
  check('primer ingreso exige cambiar contraseña', T.ck && T.j.debe_cambiar_password === true);
  check('mientras tanto el resto de la API está bloqueada → CAMBIO_PASSWORD_REQUERIDO', (await api('GET', '/api/huespedes', null, T.ck)).j.codigo === 'CAMBIO_PASSWORD_REQUERIDO');
  check('contraseña débil rechazada → 422', (await api('POST', '/api/auth/cambiar-password', { actual: tmp1, nueva: 'corta1A!' }, T.ck)).s === 422);
  check('cambio de contraseña correcto', (await api('POST', '/api/auth/cambiar-password', { actual: tmp1, nueva: 'NuevaClave#Segura9' }, T.ck)).s === 200);
  check('ya puede operar tras cambiarla', (await api('GET', '/api/huespedes', null, T.ck)).s === 200);
  check('no puede cambiar su PROPIO estado → 409', (await api('POST', `/api/usuarios/${lista.j.usuarios.find((u) => u.username === 'admin').codigo}/estado`, { estado: 'suspendida' }, AD)).s === 409);
  const susp = await api('POST', `/api/usuarios/${t1}/estado`, { estado: 'suspendida', motivo: 'prueba' }, AD);
  check('suspender', susp.s === 200);
  check('la sesión abierta de una identidad suspendida deja de servir al instante', (await api('GET', '/api/huespedes', null, T.ck)).s === 401);
  const sr = await api('POST', `/api/usuarios/${t1}/cambio-rol`, { rol: 'Auditor', justificacion: 'Rotación a auditoría interna' }, AD);
  check('solicitar cambio de rol (queda pendiente)', sr.s === 201 && sr.j.estado === 'pendiente', JSON.stringify(sr.j));
  const ap = await api('POST', `/api/usuarios/solicitudes-rol/${sr.j.id}/resolver`, { aprobar: true }, AD);
  check('otra persona aprueba → el rol cambia', ap.s === 200 && ap.j.estado === 'aprobada', JSON.stringify(ap.j));
  const propia = await api('POST', `/api/usuarios/${lista.j.usuarios.find((u) => u.username === 'admin').codigo}/cambio-rol`, { rol: 'Auditor', justificacion: 'Quiero ser auditor' }, AD);
  const auto = await api('POST', `/api/usuarios/solicitudes-rol/${propia.j.id}/resolver`, { aprobar: true }, AD);
  check('NADIE aprueba su propio cambio de rol → 403', auto.s === 403, JSON.stringify(auto.j));
  const rev = await api('POST', `/api/usuarios/${t1}/estado`, { estado: 'revocada' }, AD);
  check('revocar', rev.s === 200);
  check('una identidad revocada es irreversible → 409', (await api('POST', `/api/usuarios/${t1}/estado`, { estado: 'activa' }, AD)).s === 409);
  const lr = await login('tester1', 'NuevaClave#Segura9');
  check('login de una cuenta REVOCADA → 401 genérico (sin filtrar el estado)', lr.err?.s === 401 && lr.err.j.error === 'Credenciales incorrectas', JSON.stringify(lr.err?.j));
  const hist = await api('GET', `/api/usuarios/${t1}/historial`, null, AD);
  check('historial de estados registrado por la BD', hist.s === 200 && hist.j.historial.length >= 4, JSON.stringify(hist.j).slice(0, 150));

  sec('2) Huéspedes: cifrado, contexto persona/objeto, depuración');
  const ci = await api('POST', '/api/huespedes', guest(), R.ck);
  check('check-in → 201 hospedada', ci.s === 201 && ci.j.estado === 'hospedada' && /^R-\d+$/.test(ci.j.codigo), JSON.stringify(ci.j));
  const cod = ci.j.codigo;
  check('mismo documento con otra estancia vigente → 409', (await api('POST', '/api/huespedes', guest({ habitacion: '105' }), R.ck)).s === 409);
  check('habitación ocupada en esas fechas → 409 (restricción EXCLUDE de la BD)', (await api('POST', '/api/huespedes', guest({ documento: '7777777', nombre: 'Ana Rojas Perez' }), R.ck)).s === 409);
  check('número de tarjeta completo rechazado → 422', (await api('POST', '/api/huespedes', guest({ documento: '8888888', habitacion: '106', tarjeta_ultimos4: '4111111111111111' }), R.ck)).s === 422);
  check('sin consentimiento → 422', (await api('POST', '/api/huespedes', guest({ documento: '9999999', habitacion: '106', consentimiento: false }), R.ck)).s === 422);
  const lg = await api('GET', '/api/huespedes', null, R.ck);
  const fila = lg.j.huespedes?.find((h) => h.codigo === cod);
  check('recepción ve los datos descifrados', fila?.documento === '6543210' && fila?.telefono === '+591 71234567' && fila?.pago?.tarjeta_ultimos4 === '4417', JSON.stringify(fila));
  const la = await api('GET', '/api/huespedes', null, U.ck);
  const fa = la.j.huespedes?.find((h) => h.codigo === cod);
  check('el AUDITOR solo ve datos enmascarados (sin nombre, documento ni teléfono)', fa && fa.nombre === null && fa.documento === null && fa.telefono === null && /^•+654|^•+210/.test(fa.documento_enmascarado), JSON.stringify(fa));
  // segundo recepcionista para probar el contexto "objeto ajeno"
  const t2 = await api('POST', '/api/usuarios', { username: 'tester2', nombre: 'Tester Dos', rol: 'Recepcionista' }, AD);
  await api('POST', `/api/usuarios/${t2.j.codigo}/estado`, { estado: 'activa' }, AD);
  const T2 = await login('tester2', t2.j.password_temporal);
  await api('POST', '/api/auth/cambiar-password', { actual: t2.j.password_temporal, nueva: 'OtraClave#Fuerte77' }, T2.ck);
  const aj = await api('POST', `/api/huespedes/${cod}/checkout`, null, T2.ck);
  check('un recepcionista NO puede modificar la estancia registrada por otro → 403', aj.s === 403 && aj.j.codigo === 'DENEGADO', JSON.stringify(aj.j));
  const noMfa = await api('POST', `/api/huespedes/${cod}/anular`, { motivo: 'Cliente canceló' }, R.ck);
  // recepción ya tiene 2FA vigente (lo activó hace segundos), así que aquí debe pasar; probamos con la sesión de tester2 que no tiene 2FA:
  const sinDos = await api('POST', `/api/huespedes/${cod}/anular`, { motivo: 'Cliente canceló' }, T2.ck);
  check('anular sin 2FA configurado → bloqueado', sinDos.s === 403, JSON.stringify(sinDos.j));
  check('anular con 2FA vigente → 200', noMfa.s === 200 && noMfa.j.estado === 'anulada', JSON.stringify(noMfa.j));
  const l2 = await api('GET', '/api/huespedes', null, R.ck);
  const f2 = l2.j.huespedes.find((h) => h.codigo === cod);
  check('al anular se DEPURAN los datos personales', f2.datos_depurados && f2.documento === null && f2.telefono === null && /^C\. M\. Q\.$/.test(f2.nombre), JSON.stringify(f2));
  const c2 = await api('POST', '/api/huespedes', guest({ documento: '1112223', nombre: 'Lucia Fernandez', habitacion: '107', metodo_pago: 'efectivo', tarjeta_ultimos4: undefined }), R.ck);
  const co = await api('POST', `/api/huespedes/${c2.j.codigo}/checkout`, null, R.ck);
  check('check-out finaliza y depura', co.s === 200 && co.j.datos_depurados === true, JSON.stringify(co.j));

  sec('3) Matriz de mínimo privilegio');
  const mx = await api('GET', '/api/matriz', null, AD);
  check('admin ve la matriz', mx.s === 200 && mx.j.matriz.Auditor.bitacora?.join() === 'leer', JSON.stringify(mx.j.matriz?.Auditor));
  check('el auditor también', (await api('GET', '/api/matriz', null, U.ck)).s === 200);
  check('recepción NO', (await api('GET', '/api/matriz', null, R.ck)).s === 403);
  check('auditor no puede modificarla', (await api('PUT', '/api/matriz', { rol: 'Auditor', recurso: 'reservas', operacion: 'modificar', conceder: true }, U.ck)).s === 403);
  check('la bitácora no admite escritura para ningún rol → 422', (await api('PUT', '/api/matriz', { rol: 'Administrador', recurso: 'bitacora', operacion: 'modificar', conceder: true }, AD)).s === 422);
  check('no se puede dejar sin gestión al Administrador → 409', (await api('PUT', '/api/matriz', { rol: 'Administrador', recurso: 'configuracion', operacion: 'modificar', conceder: false }, AD)).s === 409);
  const rv = await api('PUT', '/api/matriz', { rol: 'Recepcionista', recurso: 'reservas', operacion: 'crear', conceder: false }, AD);
  const sinPerm = await api('POST', '/api/huespedes', guest({ documento: '5554443', nombre: 'Mario Soliz Vega', habitacion: '108' }), R.ck);
  check('revocar un permiso surte efecto en la siguiente petición', rv.s === 200 && sinPerm.s === 403, JSON.stringify([rv.j, sinPerm.j]));
  await api('PUT', '/api/matriz', { rol: 'Recepcionista', recurso: 'reservas', operacion: 'crear', conceder: true }, AD);
  const rg = await api('POST', '/api/huespedes', guest({ documento: '5554443', nombre: 'Mario Soliz Vega', habitacion: '108' }), R.ck);
  check('volver a concederlo restablece el acceso', rg.s === 201, JSON.stringify(rg.j));
  const codRec = lista.j.usuarios.find((u) => u.username === 'recepcion').codigo;
  const sim1 = await api('POST', '/api/matriz/evaluar', { usuario: codRec, recurso: 'reservas', operacion: 'eliminar', contexto: 'propio' }, AD);
  check('simulador: recepcionista eliminar reservas → denegado en el paso de permisos', sim1.j.permitido === false && sim1.j.pasos[3].estado === 'falla', JSON.stringify(sim1.j));
  const sim2 = await api('POST', '/api/matriz/evaluar', { usuario: codRec, recurso: 'reservas', operacion: 'modificar', contexto: 'ajeno' }, AD);
  check('simulador: modificar objeto ajeno → denegado en el paso de contexto', sim2.j.permitido === false && sim2.j.pasos[4].estado === 'falla', JSON.stringify(sim2.j));

  sec('4) Bitácora');
  const bl = await api('GET', '/api/bitacora?limite=5', null, U.ck);
  check('auditor lee la bitácora', bl.s === 200 && bl.j.registros.length === 5 && bl.j.registros[0].hash_registro.length === 64);
  check('recepción NO la lee', (await api('GET', '/api/bitacora', null, R.ck)).s === 403);
  const vf = await api('GET', '/api/bitacora/verificar', null, U.ck);
  check('la cadena de hashes es ÍNTEGRA', vf.j.integra === true && vf.j.registros > 20, JSON.stringify(vf.j));
  const ed = await api('POST', '/api/bitacora/intento-edicion', null, AD);
  check('intentar editar la bitácora lo rechaza la BD y queda registrado', ed.s === 403 && ed.j.bloqueado === true, JSON.stringify(ed.j));
  const ex = await api('GET', '/api/bitacora/exportar', null, AD);
  let pkg; try { pkg = JSON.parse(descifrar(ex.buf, 'bitacora-export', 'export')); } catch (e) { pkg = null; }
  check('exportación cifrada: se descifra con la clave y la huella coincide', ex.s === 200 && pkg?.cadena_integra === true && ex.h.get('x-huella-sha256') === sha256(ex.buf).toString('hex'), ex.s);
  check('el archivo exportado NO contiene texto en claro', !ex.buf.toString('latin1').includes('Inicio de sesión'));
  const alt = Buffer.from(ex.buf); alt[60] ^= 1;
  let det = false; try { descifrar(alt, 'bitacora-export', 'export'); } catch { det = true; }
  check('un archivo exportado alterado se detecta al descifrar', det);
  check('auditor exportar sin 2FA configurado → bloqueado', (await api('GET', '/api/bitacora/exportar', null, U.ck)).s === 403);

  sec('5) Incidentes, degradación segura y cuenta de emergencia');
  const inc = await api('POST', '/api/incidentes', { escenario: 'a' }, AD);
  check('declarar incidente (compromiso de cuenta privilegiada)', inc.s === 201 && inc.j.severidad === 'critica', JSON.stringify(inc.j));
  check('no se duplica un incidente abierto del mismo tipo → 409', (await api('POST', '/api/incidentes', { escenario: 'a' }, AD)).s === 409);
  check('recepción no gestiona incidentes', (await api('POST', '/api/incidentes', { escenario: 'b' }, R.ck)).s === 403);
  check('activar degradación segura', (await api('POST', '/api/incidentes/degradacion', { activo: true }, AD)).j.degradacion === true);
  const d1 = await api('POST', '/api/usuarios', { username: 'tester3', nombre: 'Tester Tres', rol: 'Auditor' }, AD);
  const d2 = await api('POST', `/api/huespedes/${rg.j.codigo}/anular`, { motivo: 'Prueba degradación' }, R.ck);
  const d3 = await api('GET', '/api/bitacora/exportar', null, AD);
  check('en degradación se BLOQUEA: crear identidad, anular reserva, exportar bitácora → 423', d1.s === 423 && d2.s === 423 && d3.s === 423, JSON.stringify([d1.s, d2.s, d3.s]));
  const ck2 = await api('POST', '/api/huespedes', guest({ documento: '3332221', nombre: 'Rosa Choque Apaza', habitacion: '109', metodo_pago: 'qr', tarjeta_ultimos4: undefined }), R.ck);
  check('en degradación CONTINÚAN el check-in manual y la consulta', ck2.s === 201 && (await api('GET', '/api/huespedes', null, R.ck)).s === 200, JSON.stringify(ck2.j));
  const em = await api('GET', '/api/emergencia', null, AD);
  const cuenta = em.j.cuentas?.[0]?.codigo;
  check('el custodio ve la cuenta de emergencia (deshabilitada)', cuenta === 'breakglass-01' && em.j.cuentas[0].activa === false, JSON.stringify(em.j));
  check('habilitarla exige motivo y un incidente vigente', (await api('POST', `/api/emergencia/${cuenta}/activar`, { motivo: 'corto', incidente_id: inc.j.id }, AD)).s === 422
    && (await api('POST', `/api/emergencia/${cuenta}/activar`, { motivo: 'Servicio de identidad caído, se necesita check-in manual', incidente_id: 99999 }, AD)).s === 409);
  const hab = await api('POST', `/api/emergencia/${cuenta}/activar`, { motivo: 'Servicio de identidad caído, se necesita check-in manual', incidente_id: inc.j.id }, AD);
  check('habilitar cuenta de emergencia con incidente vigente', hab.s === 201, JSON.stringify(hab.j));
  const cerr = await api('POST', `/api/emergencia/usos/${hab.j.uso_id}/cerrar`, null, AD);
  check('cerrar el uso la deshabilita', cerr.s === 200 && cerr.j.activa === false, JSON.stringify(cerr.j));
  check('el ADMIN no puede revisar su propio uso (solo el Auditor)', (await api('POST', `/api/emergencia/usos/${hab.j.uso_id}/revisar`, null, AD)).s === 403);
  const rvw = await api('POST', `/api/emergencia/usos/${hab.j.uso_id}/revisar`, null, U.ck);
  check('el Auditor revisa el uso', rvw.s === 200, JSON.stringify(rvw.j));
  check('desactivar degradación (el Administrador sigue pudiendo configurar durante ella)', (await api('POST', '/api/incidentes/degradacion', { activo: false }, AD)).j.degradacion === false);
  check('avanzar el incidente a contenido y cerrarlo', (await api('PATCH', `/api/incidentes/${inc.j.id}`, { estado: 'contenido', respuesta_aplicada: 'Credenciales rotadas' }, AD)).s === 200
    && (await api('PATCH', `/api/incidentes/${inc.j.id}`, { estado: 'cerrado' }, AD)).s === 200);
  check('un incidente no retrocede de estado → 409', (await api('PATCH', `/api/incidentes/${inc.j.id}`, { estado: 'abierto' }, AD)).s === 422);

  sec('6) Políticas y controles verificables');
  check('todos los roles ven las políticas', (await api('GET', '/api/politicas', null, R.ck)).j.politicas?.length === 8);
  const vc = await api('POST', '/api/politicas/verificar', null, U.ck);
  const fallan = (vc.j.controles || []).filter((c) => !c.cumple);
  check(`controles ejecutados contra la BD real: ${vc.j.resumen?.cumplen}/${vc.j.resumen?.total} cumplen`, vc.s === 200 && vc.j.resumen.total > 0 && fallan.every((f) => !f.error), JSON.stringify(fallan));
  if (fallan.length) console.log('     Controles que fallan:', fallan.map((f) => `${f.politica} · ${f.control}`));

  sec('7) Respaldos y restauración con control dual');
  try { execSync('node scripts/respaldo.js', { stdio: 'pipe' }); } catch (e) { console.log('     (no se pudo crear el respaldo: ' + String(e.stderr || e.message).slice(0, 150) + ')'); }
  const rl = await api('GET', '/api/respaldos', null, AD);
  const bk = rl.j.respaldos?.[0];
  check('el respaldo creado aparece registrado y cifrado', !!bk && bk.cifrado === true, JSON.stringify(rl.j).slice(0, 150));
  if (bk) {
    const vr = await api('POST', `/api/respaldos/${bk.id}/verificar`, null, AD);
    check('verificar integridad del respaldo (SHA-256)', vr.s === 200 && vr.j.integro === true, JSON.stringify(vr.j));
    const inc2 = await api('POST', '/api/incidentes', { escenario: 'd' }, AD);
    // segundo administrador con 2FA para autorizar
    const a2 = await api('POST', '/api/usuarios', { username: 'dsegundo', nombre: 'Segundo Admin', rol: 'Administrador' }, AD);
    await api('POST', `/api/usuarios/${a2.j.codigo}/estado`, { estado: 'activa' }, AD);
    const S = await login('dsegundo', a2.j.password_temporal);
    await api('POST', '/api/auth/cambiar-password', { actual: a2.j.password_temporal, nueva: 'SegundoAdmin#2026x' }, S.ck);
    const secS = await enrolar(S.ck, 'SegundoAdmin#2026x');
    const mala = await api('POST', '/api/respaldos/restauraciones', { incidente_id: inc2.j.id, respaldo_id: bk.id, autorizador: 'dsegundo', codigo: '000000', resultado: 'Restauración de prueba' }, AD);
    check('autorización dual con código 2FA falso → 403', mala.s === 403, JSON.stringify(mala.j));
    const propio = await api('POST', '/api/respaldos/restauraciones', { incidente_id: inc2.j.id, respaldo_id: bk.id, autorizador: 'admin', codigo: codigoSig(secAdmin), resultado: 'Restauración de prueba' }, AD);
    check('nadie se autoriza a sí mismo → 403', propio.s === 403, JSON.stringify(propio.j));
    const buena = await api('POST', '/api/respaldos/restauraciones', { incidente_id: inc2.j.id, respaldo_id: bk.id, autorizador: 'dsegundo', codigo: codigoSig(secS), resultado: 'Restauración de prueba en entorno aislado' }, AD);
    check('restauración autorizada por OTRO administrador con su 2FA', buena.s === 201, JSON.stringify(buena.j));
  }

  sec('8) Estado final');
  const fin = await api('GET', '/api/bitacora/verificar', null, U.ck);
  check('la cadena de la bitácora sigue ÍNTEGRA tras toda la prueba', fin.j.integra === true, JSON.stringify(fin.j));
  console.log(`\nResultado: ${ok} correctas, ${mal} fallidas`);
  process.exit(mal ? 1 : 0);
})().catch((e) => { console.error(e); process.exit(1); });
