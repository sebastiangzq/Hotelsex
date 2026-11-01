import React, { useState } from 'react';
import { api } from '../api.js';
import { card, btn, btn2, th, useCarga, Cargando, RES_COLOR, RES_TXT, TIPO_TXT, fechaHora } from '../ui.jsx';

const PAGINA = 100;
const sel = 'rounded-lg border border-slate-300 dark:border-slate-700 bg-transparent text-sm px-2 py-1.5';

export default function Auditoria({ c }) {
  const [tipo, setTipo] = useState(''), [resultado, setResultado] = useState(''), [desde, setDesde] = useState(0), [ver, setVer] = useState(null);
  const q = `/bitacora?limite=${PAGINA}&desde=${desde}${tipo ? '&tipo=' + tipo : ''}${resultado ? '&resultado=' + resultado : ''}`;
  const { d, err, recargar } = useCarga(() => api.get(q), [q]);

  const verificar = async () => { try { setVer(await api.get('/bitacora/verificar')); recargar(); } catch (e) { c.toast(e.message, 'err'); } };
  const editar = async () => {
    try { await api.post('/bitacora/intento-edicion'); } catch (e) { c.toast(e.data?.bloqueado ? '🛡️ ' + e.message : e.message, e.data?.bloqueado ? 'warn' : 'err'); recargar(); }
  };
  const exportar = async () => {
    const r = await c.act(() => api.descarga('/bitacora/exportar'));
    if (!r) return;
    const url = URL.createObjectURL(r.blob), a = document.createElement('a');
    a.href = url; a.download = r.nombre || 'bitacora.enc'; document.body.appendChild(a); a.click(); a.remove(); URL.revokeObjectURL(url);
    c.toast(`🔐 ${r.nombre || 'bitácora'} descargada · SHA-256 ${(r.huella || '').slice(0, 12)}…`);
    recargar();
  };
  if (!d) return <Cargando err={err} />;
  const fil = (set) => (e) => { set(e.target.value); setDesde(0); };
  return <div className={card}>
    <div className="flex flex-wrap gap-2 items-center mb-3"><h3 className="font-semibold mr-auto">Bitácora del sistema (append-only · {d.total} registros)</h3>
      <select className={sel} value={tipo} onChange={fil(setTipo)}><option value="">Todos los tipos</option>{Object.entries(TIPO_TXT).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
      <select className={sel} value={resultado} onChange={fil(setResultado)}><option value="">Todos los resultados</option>{Object.entries(RES_TXT).map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select>
      <button className={btn2} onClick={verificar}>Verificar integridad</button>
      <button className={btn2} onClick={editar}>Intentar editar un registro</button>
      {c.can('bitacora', 'leer') && <button className={btn} onClick={exportar}>🔐 Descargar bitácora cifrada (2FA)</button>}</div>
    {ver && <div className={'rounded-lg p-2 text-sm mb-3 ' + (ver.integra ? 'bg-emerald-500/10 text-emerald-600 dark:text-emerald-400' : 'bg-red-500/10 text-red-500')}>
      {ver.integra ? `✔ La cadena de hashes es íntegra (${ver.registros} registros): ninguno fue alterado.` : `✘ Alteración detectada en el registro ${ver.id_alterado}: ${ver.motivo}`}</div>}
    <div className="overflow-x-auto"><table className="w-full text-sm"><thead><tr>{['#', 'Fecha', 'Tipo', 'Actor', 'IP', 'Resultado', 'Detalle', 'Hash'].map((t) => <th key={t} className={th}>{t}</th>)}</tr></thead><tbody>
      {d.registros.map((l) => <tr key={l.id} className="border-t border-slate-100 dark:border-slate-800">
        <td className="px-3 py-1.5">{l.id}</td><td className="px-3 whitespace-nowrap">{fechaHora(l.ocurrido_en)}</td><td className="px-3">{TIPO_TXT[l.tipo]}</td><td className="px-3">{l.actor_nombre}</td>
        <td className="px-3 font-mono text-xs">{l.ip_origen || '—'}</td><td className={'px-3 ' + RES_COLOR[l.resultado]}>{RES_TXT[l.resultado]}</td><td className="px-3">{l.detalle}</td>
        <td className="px-3 font-mono text-xs text-slate-500" title={'previo: ' + l.hash_previo + '\nregistro: ' + l.hash_registro}>{l.hash_registro.slice(0, 10)}…</td></tr>)}</tbody></table></div>
    <div className="flex items-center gap-2 mt-3 text-sm"><button className={btn2} disabled={desde === 0} onClick={() => setDesde(Math.max(0, desde - PAGINA))}>← Más recientes</button>
      <button className={btn2} disabled={d.registros.length < PAGINA} onClick={() => setDesde(desde + PAGINA)}>Más antiguos →</button>
      <span className="text-slate-500">Mostrando {d.registros.length ? desde + 1 : 0}–{desde + d.registros.length}</span></div>
  </div>;
}
