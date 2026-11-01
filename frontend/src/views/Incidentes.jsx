import React, { useState } from 'react';
import { api } from '../api.js';
import { card, btn, btn2, btnRed, inp, th, Campo, Modal, Preguntar, useCarga, Cargando, fechaHora } from '../ui.jsx';

// Descripción y respuesta recomendada de cada escenario (los datos del incidente real los guarda el servidor)
const INC = {
  a: { t: 'Compromiso de cuenta privilegiada', d: 'Actividad anómala de un Administrador fuera de horario o desde una IP desconocida.', r: 'Suspender/revocar la identidad, forzar rotación de credenciales y activar la degradación segura.' },
  b: { t: 'Indisponibilidad del servicio de identidad', d: 'El servicio de identidad no responde; no se pueden validar credenciales nuevas.', r: 'Operar con la cuenta de emergencia y solo lectura hasta restaurar el servicio.' },
  c: { t: 'Alteración no autorizada de expedientes', d: 'Se detectó un cambio en expedientes de huéspedes sin solicitud asociada.', r: 'Bloquear escritura sensible, comparar con la bitácora y restaurar desde un respaldo verificado.' },
  d: { t: 'Pérdida o corrupción de registros', d: 'Falla la verificación de integridad de la cadena de hashes de la bitácora.', r: 'Aislar el almacén, restaurar una copia verificada y notificar a auditoría.' },
};
const SIG = { abierto: 'contenido', contenido: 'recuperado', recuperado: 'cerrado' };
const SEV = { baja: 'BAJA', media: 'MEDIA', alta: 'ALTA', critica: 'CRÍTICA' };

export default function Incidentes({ c }) {
  const [tab, setTab] = useState('escenarios');
  const admin = c.can('configuracion', 'modificar');
  const inc = useCarga(() => api.get('/incidentes'));
  const T = ([k, l]) => <button key={k} onClick={() => setTab(k)} className={'px-3 py-1.5 rounded-lg text-sm font-medium ' + (tab === k ? 'bg-indigo-600 text-white' : 'border border-slate-300 dark:border-slate-700')}>{l}</button>;
  return <div className="space-y-4">
    <div className="flex flex-wrap gap-2">{[['escenarios', 'Escenarios y degradación'], ['emergencia', 'Cuentas de emergencia'], ['respaldos', 'Respaldos y restauración']].map(T)}</div>
    {!inc.d ? <Cargando err={inc.err} /> : <>
      {tab === 'escenarios' && <Escenarios c={c} d={inc.d} admin={admin} recargar={inc.recargar} />}
      {tab === 'emergencia' && <Emergencia c={c} incidentes={inc.d.incidentes} admin={admin} />}
      {tab === 'respaldos' && <Respaldos c={c} incidentes={inc.d.incidentes} admin={admin} />}</>}
  </div>;
}

function Escenarios({ c, d, admin, recargar }) {
  const [avance, setAvance] = useState(null);
  const hay = Object.values(d.activos).some(Boolean);
  const degradacion = async () => { if (await c.act(() => api.post('/incidentes/degradacion', { activo: !d.degradacion }), d.degradacion ? 'Degradación segura desactivada.' : 'Degradación segura ACTIVADA.')) { recargar(); c.cargarYo(); } };
  const declarar = async (k) => { if (await c.act(() => api.post('/incidentes', { escenario: k }), '🚨 Incidente declarado.')) recargar(); };
  const avanzar = async (resp) => {
    const r = await c.act(() => api.patch('/incidentes/' + avance.id, { estado: avance.a, respuesta_aplicada: resp || undefined }), `Incidente #${avance.id}: ${avance.a}.`);
    if (r) { setAvance(null); recargar(); }
  };
  return <>
    <div className={card + ' flex flex-wrap items-center gap-3 ' + (d.degradacion ? 'border-amber-500' : '')}>
      <div className="flex-1"><h3 className="font-semibold">Modo de degradación segura</h3>
        <p className="text-sm text-slate-500">{d.degradacion ? 'ACTIVO: las operaciones sensibles están bloqueadas; la operación esencial continúa.' : 'Inactivo: operación normal.'}{hay && !d.degradacion && ' · Hay incidentes abiertos: se recomienda activarlo.'}</p></div>
      {admin && <button onClick={degradacion} role="switch" aria-checked={d.degradacion} aria-label="Alternar degradación segura" className={'w-16 h-8 rounded-full relative transition ' + (d.degradacion ? 'bg-amber-500' : 'bg-slate-400 dark:bg-slate-700')}>
        <span className={'absolute top-1 w-6 h-6 rounded-full bg-white transition-all ' + (d.degradacion ? 'left-9' : 'left-1')} /></button>}</div>
    <div className="grid md:grid-cols-2 gap-4">{Object.keys(INC).map((k) => {
      const id = d.activos[k], i = INC[k], real = id && d.incidentes.find((x) => x.id === id);
      return <div key={k} className={card + (id ? ' border-red-500 ring-1 ring-red-500/40' : '')}>
        <div className="flex justify-between gap-2"><h4 className="font-semibold">{id ? '🚨' : '🟢'} {i.t}</h4><span className={'text-xs font-bold ' + (id ? 'text-red-500' : 'text-slate-400')}>{id ? SEV[d.escenarios[k].sev] : 'NORMAL'}</span></div>
        <p className="text-sm text-slate-500 mt-1">{id ? i.d : 'Sin incidentes abiertos de este tipo.'}</p>
        {id && <><p className="text-sm mt-2"><b>Respuesta recomendada:</b> {i.r}</p><p className="text-xs text-slate-500 mt-1">Incidente #{id} · estado <b>{real?.estado}</b> · detectado {fechaHora(real?.detectado_en)}</p></>}
        {admin && (id ? (SIG[real?.estado] && <button className={btn2 + ' mt-3'} onClick={() => setAvance({ id, a: SIG[real.estado] })}>Pasar a «{SIG[real.estado]}»</button>)
          : <button className={btn + ' mt-3'} onClick={() => declarar(k)}>Declarar incidente</button>)}</div>;
    })}</div>
    <div className="grid md:grid-cols-2 gap-4">
      <div className={card}><h4 className="font-semibold mb-2 text-emerald-600 dark:text-emerald-400">✔ Operaciones que continúan</h4>{d.operaciones_continuan.map((o) => <div key={o.clave} className="text-sm py-1">• {o.descripcion}</div>)}</div>
      <div className={card}><h4 className="font-semibold mb-2 text-red-600 dark:text-red-400">⛔ {d.degradacion ? 'Bloqueadas ahora' : 'Se bloquearían en degradación'}</h4>
        {d.operaciones_bloqueadas.map((o) => <div key={o.clave} className={'text-sm py-1 ' + (d.degradacion ? 'line-through text-slate-500' : '')}>• {o.descripcion}</div>)}</div></div>
    <div className={card + ' overflow-x-auto'}><h3 className="font-semibold mb-2">Historial de incidentes</h3>
      <table className="w-full text-sm"><thead><tr>{['#', 'Descripción', 'Severidad', 'Estado', 'Detectado', 'Respuesta aplicada'].map((t) => <th key={t} className={th}>{t}</th>)}</tr></thead><tbody>
        {d.incidentes.map((x) => <tr key={x.id} className="border-t border-slate-100 dark:border-slate-800"><td className="px-3 py-1.5">{x.id}</td><td className="px-3">{x.descripcion}</td><td className="px-3">{SEV[x.severidad]}</td><td className="px-3">{x.estado}</td>
          <td className="px-3 whitespace-nowrap">{fechaHora(x.detectado_en)}<br /><span className="text-xs text-slate-500">{x.detectado_por}</span></td><td className="px-3 text-xs">{x.respuesta_aplicada || '—'}</td></tr>)}
        {d.incidentes.length === 0 && <tr><td colSpan="6" className="px-3 py-3 text-slate-500">Sin incidentes registrados.</td></tr>}</tbody></table></div>
    {avance && <Preguntar titulo={`Incidente #${avance.id} → ${avance.a}`} descripcion="El estado solo avanza. Puede dejar constancia de la respuesta aplicada." etiqueta="Respuesta aplicada (opcional)" minimo={0} boton="Confirmar" onOk={avanzar} onClose={() => setAvance(null)} />}
  </>;
}

function Emergencia({ c, incidentes, admin }) {
  const cu = useCarga(() => (c.can('cuentas_emergencia', 'leer') ? api.get('/emergencia') : Promise.resolve({ cuentas: [] })));
  const us = useCarga(() => api.get('/emergencia/usos'));
  const [form, setForm] = useState(null), [inc, setInc] = useState(''), abiertos = incidentes.filter((i) => i.estado !== 'cerrado');
  const auditor = c.me.rol === 'Auditor';
  const todo = () => { cu.recargar(); us.recargar(); };
  const activar = async (motivo, incidente) => {
    const r = await c.act(() => api.post(`/emergencia/${form.codigo}/activar`, { motivo, incidente_id: Number(incidente) }), `${form.codigo} habilitada. Quedó registrado el uso.`);
    if (r) { setForm(null); todo(); }
  };
  const cerrar = async (u) => { if (await c.act(() => api.post(`/emergencia/usos/${u.id}/cerrar`), 'Cuenta deshabilitada y uso cerrado.')) todo(); };
  const revisar = async (u) => { if (await c.act(() => api.post(`/emergencia/usos/${u.id}/revisar`), `Uso #${u.id} revisado.`)) todo(); };
  return <>
    <div className={card}><h3 className="font-semibold mb-1">Cuentas de emergencia (break-glass)</h3>
      <p className="text-xs text-slate-500 mb-2">Están deshabilitadas por defecto. Solo su custodio puede habilitarlas, con un incidente vigente y un motivo; cada uso lo revisa luego un Auditor.</p>
      {!cu.d ? <p className="text-sm text-slate-500">Cargando…</p> : cu.d.cuentas.length === 0 ? <p className="text-sm text-slate-500">{auditor ? 'Su rol solo consulta el registro de usos.' : 'Sin cuentas.'}</p> : cu.d.cuentas.map((x) => <div key={x.codigo} className="flex flex-wrap items-center gap-3 py-2 border-b border-slate-100 dark:border-slate-800 last:border-0 text-sm">
        <span className="font-mono">{x.codigo}</span><span className={x.activa ? 'text-red-500 font-semibold' : 'text-emerald-600'}>{x.activa ? 'HABILITADA' : 'Deshabilitada'}</span>
        <span className="text-slate-500 flex-1 min-w-[12rem]">Custodio: {x.custodio} · {x.alcance}</span>
        {admin && !x.activa && <button className={btnRed} onClick={() => { setForm(x); setInc(abiertos[0]?.id ? String(abiertos[0].id) : ''); }} disabled={abiertos.length === 0} title={abiertos.length ? '' : 'Requiere un incidente vigente'}>Habilitar (2FA)</button>}</div>)}</div>
    <div className={card + ' overflow-x-auto'}><h3 className="font-semibold mb-2">Registro de usos</h3>
      {!us.d ? <p className="text-sm text-slate-500">Cargando…</p> : <table className="w-full text-sm"><thead><tr>{['#', 'Cuenta', 'Habilitada por', 'Incidente', 'Motivo', 'Inicio', 'Fin', 'Revisión', ''].map((t) => <th key={t} className={th}>{t}</th>)}</tr></thead><tbody>
        {us.d.usos.map((u) => <tr key={u.id} className="border-t border-slate-100 dark:border-slate-800"><td className="px-3 py-1.5">{u.id}</td><td className="px-3">{u.cuenta}</td><td className="px-3">{u.usada_por}</td><td className="px-3">#{u.incidente_id}</td><td className="px-3">{u.motivo}</td>
          <td className="px-3 whitespace-nowrap">{fechaHora(u.inicio)}</td><td className="px-3 whitespace-nowrap">{u.fin ? fechaHora(u.fin) : <b className="text-red-500">en curso</b>}</td>
          <td className="px-3">{u.revisado_por ? `✔ ${u.revisado_por}` : '⏳ pendiente'}</td>
          <td className="px-3"><div className="flex gap-1">{!u.fin && admin && <button className={btn2} onClick={() => cerrar(u)}>Cerrar uso</button>}{u.fin && !u.revisado_por && auditor && <button className={btn} onClick={() => revisar(u)}>Marcar revisado</button>}</div></td></tr>)}
        {us.d.usos.length === 0 && <tr><td colSpan="9" className="px-3 py-3 text-slate-500">Nunca se ha usado una cuenta de emergencia.</td></tr>}</tbody></table>}</div>
    {form && <ActivarModal cuenta={form} abiertos={abiertos} inicial={inc} onOk={activar} onClose={() => setForm(null)} />}
  </>;
}

function ActivarModal({ cuenta, abiertos, inicial, onOk, onClose }) {
  const [inc, setInc] = useState(inicial), [m, setM] = useState(''), [oc, setOc] = useState(false);
  return <Modal title={'Habilitar ' + cuenta.codigo} onClose={onClose}>
    <p className="text-sm text-slate-500 mb-2">Operación excepcional: queda registrada en la bitácora y deberá ser revisada por un Auditor.</p>
    <Campo t="Incidente vigente que justifica el uso"><select className={inp} value={inc} onChange={(e) => setInc(e.target.value)}>{abiertos.map((i) => <option key={i.id} value={i.id}>#{i.id} · {i.descripcion} ({i.estado})</option>)}</select></Campo>
    <textarea className={inp + ' mt-2'} rows="3" placeholder="Motivo (mínimo 10 caracteres)" value={m} onChange={(e) => setM(e.target.value)} />
    <button className={btn + ' mt-3 w-full'} disabled={m.trim().length < 10 || !inc || oc} onClick={async () => { setOc(true); try { await onOk(m.trim(), inc); } finally { setOc(false); } }}>Habilitar cuenta (2FA)</button>
  </Modal>;
}

function Respaldos({ c, incidentes, admin }) {
  const { d, err, recargar } = useCarga(() => api.get('/respaldos'));
  const [f, setF] = useState({ incidente_id: '', respaldo_id: '', autorizador: '', codigo: '', resultado: '' });
  if (!d) return <Cargando err={err} />;
  const abiertos = incidentes.filter((i) => i.estado !== 'cerrado'), verificados = d.respaldos.filter((r) => r.verificado_en);
  const verificar = async (r) => {
    try { await api.post(`/respaldos/${r.id}/verificar`); c.toast(`Respaldo #${r.id}: integridad verificada.`); }
    catch (e) { c.toast(e.data?.integro === false ? `⚠️ ALERTA: el respaldo #${r.id} no coincide con su huella.` : e.message, 'err'); }
    recargar();
  };
  const registrar = async () => {
    const r = await c.act(() => api.post('/respaldos/restauraciones', { ...f, incidente_id: Number(f.incidente_id), respaldo_id: Number(f.respaldo_id) }), 'Restauración registrada con control dual.');
    if (r) { setF({ incidente_id: '', respaldo_id: '', autorizador: '', codigo: '', resultado: '' }); recargar(); }
  };
  const listo = f.incidente_id && f.respaldo_id && f.autorizador && f.codigo.length === 6 && f.resultado.trim().length >= 5;
  return <>
    <div className={card + ' overflow-x-auto'}><h3 className="font-semibold mb-1">Respaldos</h3>
      <p className="text-xs text-slate-500 mb-2">Se crean en el servidor con <code>npm run respaldo</code> (cifrados con AES-256-GCM). Aquí se verifica su integridad por huella SHA-256.</p>
      <table className="w-full text-sm"><thead><tr>{['#', 'Alcance', 'Creado', 'Huella SHA-256', 'Verificado', ''].map((t) => <th key={t} className={th}>{t}</th>)}</tr></thead><tbody>
        {d.respaldos.map((r) => <tr key={r.id} className="border-t border-slate-100 dark:border-slate-800"><td className="px-3 py-1.5">{r.id}</td><td className="px-3">{r.alcance}{r.cifrado && ' 🔐'}</td><td className="px-3 whitespace-nowrap">{fechaHora(r.creado_en)}</td>
          <td className="px-3 font-mono text-xs" title={r.sha256}>{r.sha256.slice(0, 16)}…</td><td className="px-3">{r.verificado_en ? `✔ ${r.verificado_por} · ${fechaHora(r.verificado_en)}` : '—'}</td>
          <td className="px-3">{admin && <button className={btn2} onClick={() => verificar(r)}>Verificar integridad</button>}</td></tr>)}
        {d.respaldos.length === 0 && <tr><td colSpan="6" className="px-3 py-3 text-slate-500">Aún no hay respaldos registrados.</td></tr>}</tbody></table></div>
    {admin && <div className={card}><h3 className="font-semibold mb-1">Registrar una restauración (control dual)</h3>
      <p className="text-xs text-slate-500 mb-2">Este formulario <b>registra</b> la restauración y exige un respaldo verificado, un incidente vigente y la autorización de <b>otro administrador</b> con su código 2FA. La restauración en sí (<code>pg_restore</code>) se ejecuta manualmente en el servidor.</p>
      <div className="grid sm:grid-cols-3 gap-2">
        <Campo t="Incidente"><select className={inp} value={f.incidente_id} onChange={(e) => setF({ ...f, incidente_id: e.target.value })}><option value="">Seleccione…</option>{abiertos.map((i) => <option key={i.id} value={i.id}>#{i.id} · {i.descripcion}</option>)}</select></Campo>
        <Campo t="Respaldo verificado"><select className={inp} value={f.respaldo_id} onChange={(e) => setF({ ...f, respaldo_id: e.target.value })}><option value="">Seleccione…</option>{verificados.map((r) => <option key={r.id} value={r.id}>#{r.id} · {r.alcance} · {fechaHora(r.creado_en)}</option>)}</select></Campo>
        <Campo t="Usuario del 2.º administrador"><input className={inp} value={f.autorizador} onChange={(e) => setF({ ...f, autorizador: e.target.value })} autoComplete="off" /></Campo>
        <Campo t="Código 2FA del autorizador"><input className={inp + ' font-mono tracking-widest'} inputMode="numeric" maxLength={6} value={f.codigo} onChange={(e) => setF({ ...f, codigo: e.target.value.replace(/\D/g, '') })} autoComplete="off" /></Campo>
        <div className="sm:col-span-2"><Campo t="Resultado / observaciones"><input className={inp} value={f.resultado} maxLength={300} onChange={(e) => setF({ ...f, resultado: e.target.value })} /></Campo></div></div>
      <button className={btn + ' mt-3'} disabled={!listo} onClick={registrar}>Registrar restauración</button></div>}
    <div className={card + ' overflow-x-auto'}><h3 className="font-semibold mb-2">Restauraciones registradas</h3>
      <table className="w-full text-sm"><thead><tr>{['#', 'Incidente', 'Respaldo', 'Realizada por', 'Autorizada por', 'Fecha', 'Resultado'].map((t) => <th key={t} className={th}>{t}</th>)}</tr></thead><tbody>
        {d.restauraciones.map((x) => <tr key={x.id} className="border-t border-slate-100 dark:border-slate-800"><td className="px-3 py-1.5">{x.id}</td><td className="px-3">#{x.incidente_id}</td><td className="px-3">#{x.respaldo_id}</td><td className="px-3">{x.realizada_por}</td><td className="px-3">{x.autorizada_por}</td><td className="px-3 whitespace-nowrap">{fechaHora(x.realizada_en)}</td><td className="px-3">{x.resultado}</td></tr>)}
        {d.restauraciones.length === 0 && <tr><td colSpan="7" className="px-3 py-3 text-slate-500">Sin restauraciones.</td></tr>}</tbody></table></div>
  </>;
}
