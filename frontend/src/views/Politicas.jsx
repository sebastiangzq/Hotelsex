import React, { useState } from 'react';
import { api } from '../api.js';
import { card, btn, btn2, useCarga, Cargando } from '../ui.jsx';

// Pantalla donde se puede comprobar cada política (el menú lateral se resalta mientras está seleccionada)
const DONDE = {
  P1: ['identidades', 'Tabla de identidades: códigos únicos, estados Activa/Suspendida/Revocada, historial y bloqueo de identidades revocadas.'],
  P2: [null, 'Pantalla de Login (cierre sesión para verla): “Credenciales incorrectas” genérico y contador de bloqueo.'],
  P3: ['matriz', 'Matriz de acceso (roles × recursos × operaciones) y simulador con las 5 variables de evaluación.'],
  P4: ['huespedes', 'Registro de huéspedes: consentimiento, datos cifrados, solo 4 dígitos de tarjeta y depuración al check-out.'],
  P5: ['auditoria', 'Bitácora encadenada por hash, verificación de integridad e intento de edición bloqueado por la base de datos.'],
  P6: ['identidades', 'Solicitudes de cambio de rol: se justifican y las autoriza otra persona con 2FA.'],
  P7: ['incidentes', 'Escenarios de incidente, degradación segura, respaldos y restauración con control dual.'],
  P8: ['incidentes', 'Pestaña “Cuentas de emergencia”: habilitación con incidente y motivo, y revisión del Auditor.'],
};

export default function Politicas({ c }) {
  const { d, err } = useCarga(() => api.get('/politicas'));
  const [sel, setSel] = useState(0), [ver, setVer] = useState(null), [ocupado, setOcupado] = useState(false);
  if (!d) return <Cargando err={err} />;
  const p = d.politicas[sel], [vista, donde] = DONDE[p.codigo] || [null, ''];
  const puedeVerificar = c.can('bitacora', 'leer');
  const verificar = async () => {
    setOcupado(true);
    try { setVer(await api.post('/politicas/verificar')); } catch (e) { c.toast(e.message, 'err'); } finally { setOcupado(false); }
  };
  const estadoDe = (id) => ver?.controles.find((x) => x.id === id);
  return <div className="space-y-4">
    {puedeVerificar && <div className={card + ' flex flex-wrap items-center gap-3'}>
      <div className="flex-1"><h3 className="font-semibold">Controles verificables</h3><p className="text-sm text-slate-500">Cada regla se prueba contra la base de datos real: cumple si la consulta de control no encuentra ninguna violación.</p></div>
      {ver && <span className={'text-sm font-semibold ' + (ver.resumen.fallan ? 'text-red-500' : 'text-emerald-500')}>{ver.resumen.cumplen}/{ver.resumen.total} cumplen</span>}
      <button className={btn} onClick={verificar} disabled={ocupado}>{ocupado ? 'Verificando…' : 'Ejecutar verificación'}</button></div>}
    <div className="grid md:grid-cols-2 gap-4">
      <div className="space-y-2">{d.politicas.map((x, i) => {
        const falla = ver && x.controles.some((k) => estadoDe(k.id) && !estadoDe(k.id).cumple);
        return <button key={x.id} onClick={() => { setSel(i); c.setHl(DONDE[x.codigo]?.[0] || null); }} className={'w-full text-left ' + card + (sel === i ? ' ring-2 ring-indigo-500' : ' hover:border-indigo-400')}>
          {ver && <span className="float-right">{falla ? '❌' : '✅'}</span>}<b>{x.codigo}</b> · {x.titulo}</button>;
      })}</div>
      <div className={card + ' h-fit sticky top-4'}><h3 className="font-semibold">{p.codigo} · {p.titulo}</h3>
        <p className="text-sm mt-2"><b>Regla:</b> {p.regla}</p>
        <div className="mt-3"><b className="text-sm">Controles:</b>{p.controles.map((k) => { const e = estadoDe(k.id); return <div key={k.id} className="text-sm py-1.5 border-b border-slate-100 dark:border-slate-800 last:border-0">
          {e ? (e.cumple ? '✅ ' : '❌ ') : '• '}{k.control}<div className="text-xs text-slate-500">Mecanismo: {k.mecanismo}{e && !e.cumple && (e.error ? ` · error: ${e.error}` : ` · ${e.filas_fallo} violación(es)`)}</div></div>; })}</div>
        <p className="text-sm mt-3"><b>Se comprueba en:</b> {donde}</p>
        {vista ? <button className={btn + ' mt-4'} onClick={() => c.ir(vista)}>Ir a la pantalla →</button> : <button className={btn2 + ' mt-4'} onClick={c.salir}>Cerrar sesión para ver el Login</button>}
        <p className="text-xs text-slate-500 mt-3">El elemento del menú lateral se resalta mientras la política está seleccionada.</p></div></div>
  </div>;
}
