import React, { useEffect, useState } from 'react';

export const card = 'rounded-xl border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-900 p-4 shadow-sm';
export const btn = 'px-3 py-1.5 rounded-lg text-sm font-medium bg-indigo-600 text-white hover:bg-indigo-500 disabled:opacity-40 disabled:cursor-not-allowed';
export const btn2 = 'px-3 py-1.5 rounded-lg text-sm font-medium border border-slate-300 dark:border-slate-700 hover:bg-slate-100 dark:hover:bg-slate-800 disabled:opacity-40 disabled:cursor-not-allowed';
export const btnRed = 'px-3 py-1.5 rounded-lg text-sm font-medium bg-red-600 text-white hover:bg-red-500 disabled:opacity-40 disabled:cursor-not-allowed';
export const inp = 'w-full rounded-lg border border-slate-300 dark:border-slate-700 bg-white dark:bg-slate-950 px-3 py-2 text-sm';
export const th = 'text-left px-3 py-2 text-xs uppercase tracking-wide text-slate-500';

export const RECURSOS = {
  reservas: 'Reservas', expedientes_huespedes: 'Expedientes de huéspedes', facturacion: 'Facturación',
  configuracion: 'Configuración', bitacora: 'Bitácora', cuentas_emergencia: 'Cuentas de emergencia',
};
export const OPS = { leer: 'Leer', crear: 'Crear', modificar: 'Modificar', eliminar: 'Eliminar' };
export const ESTADO_ID = {
  activa: ['Activa', 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300'],
  suspendida: ['Suspendida', 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300'],
  revocada: ['Revocada', 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300'],
};
export const RES_COLOR = {
  exito: 'text-emerald-600 dark:text-emerald-400', fallo: 'text-red-600 dark:text-red-400',
  denegado: 'text-red-600 dark:text-red-400', solicitado: 'text-amber-600 dark:text-amber-400',
};
export const RES_TXT = { exito: 'Éxito', fallo: 'Fallo', denegado: 'Denegado', solicitado: 'Solicitado' };
export const TIPO_TXT = {
  autenticacion: 'Autenticación', autorizacion: 'Autorización', cambio_rol: 'Cambio de rol', acceso_denegado: 'Acceso denegado',
  cuenta_emergencia: 'Cuenta de emergencia', configuracion: 'Configuración', identidad: 'Identidad', huesped: 'Huésped', incidente: 'Incidente',
};
export const fechaHora = (v) => (v ? new Date(v).toLocaleString('es-BO') : '—');

export const Badge = ({ e }) => <span className={'px-2 py-0.5 rounded-full text-xs font-medium ' + ESTADO_ID[e][1]}>{ESTADO_ID[e][0]}</span>;

export const Modal = ({ children, title, onClose, ancho = 'max-w-md' }) => (
  <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 p-4 overflow-y-auto" role="dialog" aria-modal="true">
    <div className={card + ' w-full ' + ancho}>
      <div className="flex justify-between mb-3 gap-2">
        <h3 className="font-semibold">{title}</h3>
        {onClose && <button onClick={onClose} className="text-slate-500" aria-label="Cerrar">✕</button>}
      </div>
      {children}
    </div>
  </div>
);

export const Campo = ({ t, children }) => <div><label className="text-xs text-slate-500">{t}</label>{children}</div>;

/** Carga datos de la API al montar y ofrece recargar. */
export function useCarga(fn, deps = []) {
  const [d, setD] = useState(null), [err, setErr] = useState(null);
  const recargar = async () => {
    try { setD(await fn()); setErr(null); } catch (e) { setErr(e); }
  };
  useEffect(() => { recargar(); /* eslint-disable-next-line */ }, deps);
  return { d, err, recargar };
}

export const Cargando = ({ err }) => err
  ? <div className={card + ' text-sm text-red-600 dark:text-red-400'}>{err.status === 403 ? 'Su rol no tiene permiso para ver esta información.' : err.message}</div>
  : <div className={card + ' text-sm text-slate-500'}>Cargando…</div>;

/** Petición de confirmación con campo de texto opcional (motivo, justificación…) */
export function Preguntar({ titulo, descripcion, etiqueta, minimo = 0, textarea = true, onOk, onClose, boton = 'Confirmar' }) {
  const [v, setV] = useState(''), [ocupado, setOcupado] = useState(false);
  const ok = v.trim().length >= minimo;
  const enviar = async () => { setOcupado(true); try { await onOk(v.trim()); } finally { setOcupado(false); } };
  return <Modal title={titulo} onClose={onClose}>
    {descripcion && <p className="text-sm text-slate-500 mb-2">{descripcion}</p>}
    {etiqueta && (textarea
      ? <textarea className={inp} rows="3" placeholder={etiqueta} value={v} onChange={(e) => setV(e.target.value)} />
      : <input className={inp} placeholder={etiqueta} value={v} onChange={(e) => setV(e.target.value)} />)}
    <button className={btn + ' mt-3 w-full'} disabled={!ok || ocupado} onClick={enviar}>{boton}</button>
  </Modal>;
}
