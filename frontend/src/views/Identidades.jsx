import React, { useState } from 'react';
import { api } from '../api.js';
import { card, btn, btn2, inp, th, Badge, Modal, Preguntar, Campo, useCarga, Cargando, fechaHora } from '../ui.jsx';

const ROLES = ['Administrador', 'Recepcionista', 'Auditor'];
const TXT_ESTADO = { activa: 'Activa', suspendida: 'Suspendida', revocada: 'Revocada' };

export default function Identidades({ c }) {
  const us = useCarga(() => api.get('/usuarios'));
  const sol = useCarga(() => api.get('/usuarios/solicitudes-rol'));
  const [f, setF] = useState({ username: '', nombre: '', rol: 'Recepcionista', email: '' });
  const [cambio, setCambio] = useState(null), [nr, setNr] = useState('Recepcionista');
  const [pend, setPend] = useState(null), [temporal, setTemporal] = useState(null), [hist, setHist] = useState(null);
  if (!us.d) return <Cargando err={us.err} />;
  const todo = () => { us.recargar(); sol.recargar(); };

  const crear = async () => {
    if (!f.username.trim() || !f.nombre.trim()) return c.toast('Complete usuario y nombre.', 'warn');
    const r = await c.act(() => api.post('/usuarios', { ...f, email: f.email || undefined }));
    if (r) { setTemporal(r); setF({ username: '', nombre: '', rol: 'Recepcionista', email: '' }); todo(); }
  };
  const estado = async (u, nuevo, motivo) => {
    const r = await c.act(() => api.post(`/usuarios/${u.codigo}/estado`, { estado: nuevo, motivo: motivo || undefined }), `${u.codigo}: ${TXT_ESTADO[u.estado]} → ${TXT_ESTADO[nuevo]}`);
    if (r) todo(); return r;
  };
  const verHistorial = async (u) => { try { setHist({ u, filas: (await api.get(`/usuarios/${u.codigo}/historial`)).historial }); } catch (e) { c.toast(e.message, 'err'); } };
  const solicitar = async (justificacion) => {
    const r = await c.act(() => api.post(`/usuarios/${cambio.codigo}/cambio-rol`, { rol: nr, justificacion }), 'Solicitud de cambio de rol registrada (pendiente de autorización).');
    if (r) { setCambio(null); todo(); }
  };
  const resolver = async (s, aprobar) => {
    const r = await c.act(() => api.post(`/usuarios/solicitudes-rol/${s.id}/resolver`, { aprobar }), aprobar ? 'Cambio de rol aprobado y aplicado.' : 'Solicitud rechazada.');
    if (r) todo();
  };

  return <div className="space-y-4">
    <div className={card}><h3 className="font-semibold mb-2">Crear identidad única</h3>
      <div className="grid sm:grid-cols-5 gap-2">
        <input className={inp} placeholder="usuario (minúsculas)" value={f.username} onChange={(e) => setF({ ...f, username: e.target.value })} maxLength={32} />
        <input className={inp} placeholder="Nombre completo" value={f.nombre} onChange={(e) => setF({ ...f, nombre: e.target.value })} maxLength={100} />
        <input className={inp} placeholder="Correo (opcional)" value={f.email} onChange={(e) => setF({ ...f, email: e.target.value })} maxLength={120} />
        <select className={inp} value={f.rol} onChange={(e) => setF({ ...f, rol: e.target.value })}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
        <button className={btn} onClick={crear}>Crear identidad (2FA)</button></div>
      <p className="text-xs text-slate-500 mt-2">Las identidades nuevas nacen “Suspendidas”, con una contraseña temporal aleatoria que se muestra una sola vez y debe cambiarse en el primer ingreso. Luego se activan con “Alta”.</p></div>

    <div className={card + ' overflow-x-auto'}><table className="w-full text-sm"><thead><tr>{['Código', 'Usuario', 'Nombre', 'Rol', 'Estado', '2FA', 'Acciones'].map((t) => <th key={t} className={th}>{t}</th>)}</tr></thead><tbody>
      {us.d.usuarios.map((u) => {
        const yoMismo = u.username === c.me.username;
        return <tr key={u.codigo} className="border-t border-slate-100 dark:border-slate-800">
          <td className="px-3 py-2 font-mono">{u.codigo}</td><td className="px-3">{u.username}{yoMismo && <span className="text-xs text-slate-500"> (usted)</span>}</td><td className="px-3">{u.nombre}</td><td className="px-3">{u.rol}</td>
          <td className="px-3"><Badge e={u.estado} /></td><td className="px-3">{u.mfa_habilitado ? '🔐' : '—'}</td>
          <td className="px-3 py-2"><div className="flex flex-wrap gap-1.5">
            <button className={btn2} onClick={() => verHistorial(u)}>Historial</button>
            {u.estado === 'revocada' ? <span className="text-xs text-slate-500 self-center">🔒 Irreversible</span> : <>
              {u.estado === 'suspendida' && <button className={btn2} disabled={yoMismo} onClick={() => estado(u, 'activa')}>Alta</button>}
              {u.estado === 'activa' && <button className={btn2} disabled={yoMismo} onClick={() => setPend({ u, nuevo: 'suspendida' })}>Suspender</button>}
              <button className={btn2} disabled={yoMismo} onClick={() => setPend({ u, nuevo: 'revocada' })}>Baja (revocar)</button>
              <button className={btn2} onClick={() => { setCambio(u); setNr(u.rol); }}>Cambiar de rol</button></>}
          </div></td></tr>;
      })}</tbody></table></div>

    <div className={card}><h3 className="font-semibold mb-2">Solicitudes de cambio de rol</h3>
      {!sol.d ? <p className="text-sm text-slate-500">Cargando…</p> : sol.d.solicitudes.length === 0
        ? <p className="text-sm text-slate-500">Sin solicitudes. Use “Cambiar de rol” para iniciar el flujo: la solicitud la debe resolver otra persona.</p>
        : sol.d.solicitudes.map((s) => <div key={s.id} className="flex flex-wrap items-center gap-2 text-sm py-1.5 border-b border-slate-100 dark:border-slate-800 last:border-0">
          <span className="font-mono">{s.usuario}</span><span>{s.rol_actual} → <b>{s.rol_nuevo}</b></span>
          <span className="text-slate-500 flex-1 min-w-[12rem]">“{s.justificacion}” · solicitado por {s.solicitado_por} · {fechaHora(s.solicitado_en)}</span>
          {s.estado === 'pendiente' ? <><button className={btn} onClick={() => resolver(s, true)}>Autorizar (2FA)</button><button className={btn2} onClick={() => resolver(s, false)}>Rechazar</button></>
            : <span className={s.estado === 'aprobada' ? 'text-emerald-500' : 'text-red-500'}>{s.estado === 'aprobada' ? 'Aprobada' : 'Rechazada'}{s.resuelto_por && ` por ${s.resuelto_por}`}</span>}</div>)}</div>

    {cambio && <Modal title={'Solicitar cambio de rol · ' + cambio.codigo} onClose={() => setCambio(null)}>
      <p className="text-sm text-slate-500 mb-2">El cambio no se aplica hasta que otra persona lo autorice. Rol actual: <b>{cambio.rol}</b>.</p>
      <select className={inp + ' mb-1'} value={nr} onChange={(e) => setNr(e.target.value)}>{ROLES.map((r) => <option key={r}>{r}</option>)}</select>
      <Preguntarinline onOk={solicitar} /></Modal>}
    {pend && <Preguntar titulo={`${pend.nuevo === 'revocada' ? 'Revocar' : 'Suspender'} · ${pend.u.codigo}`} descripcion={pend.nuevo === 'revocada' ? 'La revocación es IRREVERSIBLE y cierra todas las sesiones de la identidad.' : 'Se cerrarán las sesiones abiertas de la identidad.'}
      etiqueta="Motivo (opcional)" minimo={0} boton="Confirmar (2FA)" onClose={() => setPend(null)} onOk={async (m) => { if (await estado(pend.u, pend.nuevo, m)) setPend(null); }} />}
    {temporal && <Modal title="Identidad creada" onClose={() => setTemporal(null)}>
      <p className="text-sm">Usuario <b>{temporal.username}</b> · {temporal.codigo} · rol {temporal.rol} · estado <b>suspendida</b>.</p>
      <p className="text-sm mt-2">Contraseña temporal (se muestra <b>una sola vez</b>):</p>
      <code className="block mt-1 p-2 rounded bg-slate-100 dark:bg-slate-800 text-center text-lg select-all">{temporal.password_temporal}</code>
      <p className="text-xs text-slate-500 mt-2">{temporal.aviso}</p><button className={btn + ' w-full mt-3'} onClick={() => setTemporal(null)}>Entendido, ya la copié</button></Modal>}
    {hist && <Modal title={'Historial · ' + hist.u.codigo} onClose={() => setHist(null)} ancho="max-w-xl">
      {hist.filas.length === 0 ? <p className="text-sm text-slate-500">Sin movimientos.</p> : <div className="max-h-80 overflow-y-auto text-sm">{hist.filas.map((h, i) => <div key={i} className="py-1.5 border-b border-slate-100 dark:border-slate-800 last:border-0">
        <b>{h.tipo_movimiento}</b> {h.estado_anterior && `${h.estado_anterior} → `}{h.estado_nuevo} <span className="text-slate-500">· {h.realizado_por || 'sistema'} · {fechaHora(h.ocurrido_en)}{h.motivo && ` · ${h.motivo}`}</span></div>)}</div>}</Modal>}
  </div>;
}

// Campo de justificación obligatoria dentro del modal de cambio de rol
function Preguntarinline({ onOk }) {
  const [j, setJ] = useState(''), [oc, setOc] = useState(false);
  return <>
    <textarea className={inp} rows="3" placeholder="Justificación (obligatoria, mínimo 5 caracteres)" value={j} onChange={(e) => setJ(e.target.value)} />
    <button className={btn + ' mt-3 w-full'} disabled={j.trim().length < 5 || oc} onClick={async () => { setOc(true); try { await onOk(j.trim()); } finally { setOc(false); } }}>Enviar solicitud (2FA)</button>
  </>;
}
