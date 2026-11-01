import React, { useEffect, useState } from 'react';
import { api } from '../api.js';
import { card, btn, inp, th, Campo, useCarga, Cargando, RECURSOS, OPS } from '../ui.jsx';

export default function Matriz({ c }) {
  const m = useCarga(() => api.get('/matriz'));
  const us = useCarga(() => api.get('/matriz/usuarios'));
  const [s, setS] = useState({ usuario: '', operacion: 'modificar', recurso: 'reservas', contexto: 'propio' });
  const [res, setRes] = useState(null), [n, setN] = useState(0);
  const edita = c.can('configuracion', 'modificar');
  useEffect(() => { if (res && n < res.pasos.length) { const t = setTimeout(() => setN(n + 1), 450); return () => clearTimeout(t); } }, [n, res]);
  useEffect(() => { if (us.d && !s.usuario && us.d.usuarios[0]) setS((x) => ({ ...x, usuario: us.d.usuarios[0].codigo })); }, [us.d]);
  if (!m.d) return <Cargando err={m.err} />;
  const catalogo = new Set(m.d.catalogo.map((x) => x.recurso + ':' + x.operacion));

  const toggle = async (rol, recurso, operacion) => {
    if (!edita) return;
    const on = (m.d.matriz[rol][recurso] || []).includes(operacion);
    const r = await c.act(() => api.put('/matriz', { rol, recurso, operacion, conceder: !on }), `${rol} · ${RECURSOS[recurso]} · ${OPS[operacion]}: ${on ? 'retirado' : 'concedido'}.`);
    if (r) { m.recargar(); c.cargarYo(); }
  };
  const evaluar = async () => {
    try { const r = await api.post('/matriz/evaluar', s); setRes(r); setN(0); } catch (e) { c.toast(e.message, 'err'); }
  };
  const mostrados = res ? res.pasos.slice(0, n) : [], fin = res && n >= res.pasos.length;
  return <div className="space-y-4">
    <div className={card + ' overflow-x-auto'}><div className="flex justify-between items-center mb-2 gap-2 flex-wrap"><h3 className="font-semibold">Matriz de control de acceso</h3>
      <span className="text-xs text-slate-500">{edita ? 'Pulse una operación para concederla o retirarla (pide 2FA)' : 'Solo lectura para su rol'}</span></div>
      <table className="w-full text-sm"><thead><tr><th className={th}>Recurso</th>{m.d.roles.map((r) => <th key={r} className={th}>{r}</th>)}</tr></thead><tbody>
        {m.d.recursos.map((rec) => <tr key={rec} className="border-t border-slate-100 dark:border-slate-800"><td className="px-3 py-2">{RECURSOS[rec]}</td>
          {m.d.roles.map((r) => <td key={r} className="px-3"><div className="flex gap-1">{m.d.operaciones.map((op) => {
            if (!catalogo.has(rec + ':' + op)) return <span key={op} title="No existe para este recurso (la bitácora es inalterable)" className="w-6 h-6 rounded text-[11px] flex items-center justify-center text-slate-300 dark:text-slate-700">·</span>;
            const on = (m.d.matriz[r][rec] || []).includes(op);
            return <button key={op} title={OPS[op]} disabled={!edita} onClick={() => toggle(r, rec, op)}
              className={'w-6 h-6 rounded text-[11px] font-bold ' + (on ? 'bg-indigo-600 text-white' : 'bg-slate-200 dark:bg-slate-800 text-slate-400') + (edita ? '' : ' cursor-default')}>{OPS[op][0]}</button>;
          })}</div></td>)}</tr>)}
      </tbody></table><p className="text-xs text-slate-500 mt-2">L = Leer · C = Crear · M = Modificar · E = Eliminar. Lo que no está concedido se niega. Retirar un permiso cierra su vigencia: queda el rastro.</p></div>

    <div className={card}><h3 className="font-semibold mb-3">Simulador · Evaluación en el servidor</h3>
      <div className="grid sm:grid-cols-5 gap-2">
        <Campo t="Identidad"><select className={inp} value={s.usuario} onChange={(e) => setS({ ...s, usuario: e.target.value })}>{(us.d?.usuarios || []).map((u) => <option key={u.codigo} value={u.codigo}>{u.username} ({u.rol}, {u.estado})</option>)}</select></Campo>
        <Campo t="Operación"><select className={inp} value={s.operacion} onChange={(e) => setS({ ...s, operacion: e.target.value })}>{m.d.operaciones.map((o) => <option key={o} value={o}>{OPS[o]}</option>)}</select></Campo>
        <Campo t="Recurso"><select className={inp} value={s.recurso} onChange={(e) => setS({ ...s, recurso: e.target.value })}>{m.d.recursos.map((r) => <option key={r} value={r}>{RECURSOS[r]}</option>)}</select></Campo>
        <Campo t="Contexto (objeto)"><select className={inp} value={s.contexto} onChange={(e) => setS({ ...s, contexto: e.target.value })}><option value="propio">Propio / asignado</option><option value="ajeno">Ajeno</option></select></Campo>
        <div className="flex items-end"><button className={btn + ' w-full'} onClick={evaluar} disabled={!s.usuario}>Evaluar</button></div></div>
      <p className="text-xs text-slate-500 mt-2">Usa la misma función <code>evaluar_acceso</code> de la base de datos que protege al sistema real.</p>
      <div className="mt-4 space-y-2">{mostrados.map((x, i) => <div key={i} className={'rounded-lg p-3 text-sm border ' + (x.estado === 'ok' ? 'border-emerald-500/50 bg-emerald-500/10' : x.estado === 'falla' ? 'border-red-500/50 bg-red-500/10' : 'border-slate-300 dark:border-slate-700 opacity-60')}>
        <b>{x.estado === 'ok' ? '✔' : x.estado === 'falla' ? '✘' : '–'} {i + 1} · {x.nombre}</b>{x.detalle && <div className="text-xs mt-0.5">{x.detalle}</div>}{x.estado === 'omitido' && <div className="text-xs mt-0.5">No evaluado: denegación por defecto</div>}</div>)}
        {fin && <div className={'rounded-lg p-3 font-bold text-center text-white ' + (res.permitido ? 'bg-emerald-600' : 'bg-red-600')}>{res.permitido ? 'ACCESO CONCEDIDO' : 'ACCESO DENEGADO'}</div>}</div></div>
  </div>;
}
