import React from 'react';
import { api } from '../api.js';
import { card, btn, btn2, useCarga, Cargando, RES_COLOR, RES_TXT, TIPO_TXT, fechaHora } from '../ui.jsx';

const COLOR = { ocupada: 'bg-indigo-500', libre: 'bg-emerald-500', limpieza: 'bg-amber-500' };

export default function Dashboard({ c }) {
  const { d, err, recargar } = useCarga(() => api.get('/panel'));
  if (!d) return <Cargando err={err} />;
  const liberar = async (h) => { if (await c.act(() => api.post(`/habitaciones/${h.numero}/liberar`), `Habitación ${h.numero} liberada.`)) recargar(); };
  const puedeLiberar = c.can('reservas', 'modificar');
  const tarjetas = [['Ocupación', d.ocupacion_pct + '%'], ['Ingresos de hoy', d.ingresos_hoy],
    ['Alertas activas', d.incidentes_activos ?? '—'], ['Eventos denegados/fallidos (24 h)', d.fallos_24h ?? '—']];
  return <div className="space-y-4">
    <div className="grid grid-cols-2 lg:grid-cols-4 gap-3">
      {tarjetas.map(([a, b]) => <div key={a} className={card}><div className="text-xs text-slate-500">{a}</div><div className="text-2xl font-bold">{b}</div></div>)}
    </div>
    <div className="grid lg:grid-cols-2 gap-4">
      <div className={card}><h3 className="font-semibold mb-2">Su seguridad</h3>
        <p className="text-sm">Segundo factor (2FA): <b>{c.yo.mfa.habilitado ? 'habilitado' : 'no configurado'}</b></p>
        <p className="text-xs text-slate-500 mt-1">El código se pide al realizar operaciones de alto riesgo (alta o baja de identidades, cambios de rol, matriz de acceso, exportar la bitácora, anular reservas…). Después de validarlo, vale unos minutos.</p>
        {!c.yo.mfa.habilitado && <button className={btn + ' mt-3'} onClick={c.configurar2fa}>Configurar segundo factor</button>}
      </div>
      <div className={card}><h3 className="font-semibold mb-2">Habitaciones ({d.ocupadas}/{d.total} ocupadas)</h3>
        <div className="grid grid-cols-9 gap-1.5">{d.habitaciones.map((h) => {
          const lista = h.estado === 'limpieza' && puedeLiberar;
          return <button key={h.numero} disabled={!lista} onClick={() => liberar(h)}
            title={`${h.numero} · ${h.tipo} · Bs ${h.tarifa_noche} · ${h.estado}${lista ? ' (pulse para marcar como libre)' : ''}`}
            className={'h-8 rounded text-[10px] text-white flex items-center justify-center ' + COLOR[h.estado] + (lista ? ' ring-2 ring-white/60 cursor-pointer' : ' cursor-default')}>{h.numero}</button>;
        })}</div>
        <div className="flex gap-3 text-xs mt-2 text-slate-500"><span>🟦 Ocupada</span><span>🟩 Libre</span><span>🟧 Limpieza{puedeLiberar && ' (pulse para liberar)'}</span></div></div>
    </div>
    {d.eventos_recientes && <div className={card}><div className="flex justify-between mb-2"><h3 className="font-semibold">Últimos eventos de seguridad</h3><button className={btn2} onClick={recargar}>Actualizar</button></div>
      {d.eventos_recientes.map((l) => <div key={l.id} className="text-sm flex flex-wrap gap-x-3 py-1 border-b border-slate-100 dark:border-slate-800 last:border-0">
        <span className="text-slate-500 w-40 shrink-0">{fechaHora(l.ocurrido_en)}</span><span className="w-40 shrink-0">{TIPO_TXT[l.tipo]}</span>
        <span className={RES_COLOR[l.resultado] + ' w-20 shrink-0'}>{RES_TXT[l.resultado]}</span><span className="text-slate-500 flex-1 min-w-[12rem]">{l.actor_nombre} · {l.detalle}</span></div>)}</div>}
  </div>;
}
