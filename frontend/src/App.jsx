import React, { useEffect, useRef, useState } from 'react';
import { api, onSesionExpirada } from './api.js';
import { btn2, Modal } from './ui.jsx';
import { Login, CambiarPassword, MfaModal } from './auth.jsx';
import Dashboard from './views/Dashboard.jsx';
import Huespedes from './views/Huespedes.jsx';
import Identidades from './views/Identidades.jsx';
import Matriz from './views/Matriz.jsx';
import Auditoria from './views/Auditoria.jsx';
import Incidentes from './views/Incidentes.jsx';
import Politicas from './views/Politicas.jsx';

// [vista, etiqueta, icono, recurso y operación de la matriz que la habilita]
const NAV = [
  ['dashboard', 'Panel principal', '🏨', 'reservas'], ['huespedes', 'Huéspedes', '🛎️', 'expedientes_huespedes'],
  ['identidades', 'Identidades', '🪪', 'configuracion'], ['matriz', 'Autorización', '🛡️', 'bitacora'],
  ['auditoria', 'Auditoría', '📜', 'bitacora'], ['incidentes', 'Incidentes y continuidad', '🚨', 'bitacora'], ['politicas', 'Políticas', '✅', 'reservas'],
];
const VISTAS = { dashboard: Dashboard, huespedes: Huespedes, identidades: Identidades, matriz: Matriz, auditoria: Auditoria, incidentes: Incidentes, politicas: Politicas };

export default function App() {
  const [dark, setDark] = useState(document.documentElement.classList.contains('dark'));
  useEffect(() => {
    document.documentElement.classList.toggle('dark', dark);
    try { localStorage.setItem('hs-tema', dark ? 'dark' : 'light'); } catch { /* almacenamiento no disponible */ }
  }, [dark]);

  const [yo, setYo] = useState(undefined);          // undefined = comprobando · null = sin sesión
  const [vista, setVista] = useState('dashboard'), [col, setCol] = useState(false), [hl, setHl] = useState(null);
  const [tst, setTst] = useState(null), [mfa, setMfa] = useState(null);
  const tmr = useRef(null), habiaSesion = useRef(false);

  const toast = (m, k = 'ok') => { setTst({ m, k }); clearTimeout(tmr.current); tmr.current = setTimeout(() => setTst(null), 4500); };
  const cargarYo = async () => { try { const d = await api.get('/auth/yo'); habiaSesion.current = true; setYo(d); return d; } catch { setYo(null); return null; } };
  useEffect(() => { onSesionExpirada(() => { if (!habiaSesion.current) return; habiaSesion.current = false; setYo(null); toast('Su sesión terminó. Inicie sesión de nuevo.', 'warn'); }); cargarYo(); }, []);

  const can = (recurso, op) => !!yo?.permisos?.[recurso]?.includes(op);
  const salir = async () => { try { await api.post('/auth/logout'); } catch { /* la sesión ya no existía */ } habiaSesion.current = false; setYo(null); setVista('dashboard'); setMfa(null); };

  const pedirMfa = (e) => new Promise((resolve, reject) => setMfa({ modo: e.codigo === 'MFA_REQUERIDO' ? 'verificar' : 'enrolar', operacion: e.data.operacion, resolve, reject }));
  const configurar2fa = () => pedirMfa({ codigo: 'MFA_NO_CONFIGURADO', data: {} }).then(() => toast('Segundo factor habilitado.')).catch(() => {});

  /** Ejecuta una operación de la API. Si el servidor exige 2FA, lo pide y reintenta UNA vez. Devuelve el resultado, o null si falló (ya avisó). */
  const act = async (fn, ok) => {
    try {
      let r;
      try { r = await fn(); }
      catch (e) {
        if (e.codigo !== 'MFA_REQUERIDO' && e.codigo !== 'MFA_NO_CONFIGURADO') throw e;
        await pedirMfa(e); r = await fn();
      }
      if (ok) toast(ok);
      return r ?? true;
    } catch (e) { if (!e.cancelado) toast(e.message, e.status === 423 ? 'warn' : 'err'); return null; }
  };
  const mfaListo = async () => { const m = mfa; setMfa(null); await cargarYo(); m.resolve(); };
  const mfaCancelar = () => { const m = mfa; setMfa(null); m.reject({ cancelado: true }); };

  const ir = (v) => {
    const n = NAV.find((x) => x[0] === v);
    if (!can(n[3], 'leer')) return toast('Acceso denegado: su rol no tiene permiso para este módulo.', 'err');
    setVista(v);
  };

  if (yo === undefined) return <div className="min-h-screen flex items-center justify-center text-slate-500">Cargando…</div>;
  if (!yo) return <><Login onEntrar={cargarYo} dark={dark} setDark={setDark} />{tst && <Aviso t={tst} />}</>;
  if (yo.debe_cambiar_password) return <CambiarPassword minimo={yo.politica_password.min_longitud} onListo={cargarYo} onSalir={salir} />;

  const c = { yo, me: yo.usuario, can, toast, act, ir, setHl, cargarYo, configurar2fa, salir };
  const V = VISTAS[vista];
  const mfaVigente = yo.mfa.vigente_hasta && new Date(yo.mfa.vigente_hasta) > new Date();
  return <div className="flex min-h-screen">
    <aside className={(col ? 'w-16' : 'w-60') + ' shrink-0 bg-slate-900 text-slate-200 flex flex-col transition-all'}>
      <div className="p-4 flex items-center gap-2 font-bold"><span>🏨</span>{!col && 'HotelSec'}</div>
      <nav className="flex-1 px-2 space-y-1">{NAV.map(([k, l, ic, rec]) => <button key={k} onClick={() => ir(k)} title={l}
        className={'w-full flex items-center gap-3 px-3 py-2 rounded-lg text-sm text-left ' + (vista === k ? 'bg-indigo-600 text-white' : 'hover:bg-slate-800') + (hl === k ? ' ring-2 ring-amber-400 animate-pulse' : '')}>
        <span>{ic}</span>{!col && <span className="flex-1">{l}</span>}{!col && !can(rec, 'leer') && <span>🔒</span>}</button>)}</nav>
      <button className="p-3 text-xs text-slate-400 hover:text-white" onClick={() => setCol(!col)}>{col ? '»' : '« Colapsar menú'}</button>
    </aside>
    <main className="flex-1 min-w-0">
      <header className="flex flex-wrap items-center gap-3 px-4 py-3 bg-white dark:bg-slate-900 border-b border-slate-200 dark:border-slate-800">
        <h2 className="font-semibold mr-auto">{NAV.find((n) => n[0] === vista)[1]}</h2>
        {yo.modo_degradacion && <span className="px-2 py-1 rounded-lg bg-amber-500 text-black text-xs font-bold">MODO DEGRADADO</span>}
        <span className={'text-xs px-2 py-1 rounded-lg ' + (yo.mfa.habilitado ? 'bg-emerald-500/15 text-emerald-600 dark:text-emerald-400' : 'bg-amber-500/15 text-amber-600 dark:text-amber-400')}
          title={yo.mfa.habilitado ? (mfaVigente ? 'Verificado recientemente' : 'Se pedirá el código en operaciones de alto riesgo') : 'Aún no configuró el segundo factor'}>
          {yo.mfa.habilitado ? '🔐 2FA activo' : '⚠️ Sin 2FA'}</span>
        <span className="text-sm text-slate-500">{yo.usuario.nombre} · <b>{yo.usuario.rol}</b></span>
        <button className={btn2} onClick={() => setDark(!dark)} aria-label="Cambiar tema">{dark ? '☀️' : '🌙'}</button>
        <button className={btn2} onClick={salir}>Salir</button>
      </header>
      <div className="p-4"><V key={vista} c={c} /></div>
    </main>
    {mfa && <MfaModal modo={mfa.modo} operacion={mfa.operacion} onListo={mfaListo} onCancelar={mfaCancelar} />}
    {tst && <Aviso t={tst} />}
  </div>;
}

const Aviso = ({ t }) => <div role="status" className={'fixed bottom-4 right-4 z-[60] max-w-sm rounded-lg px-4 py-3 text-sm text-white shadow-lg ' + (t.k === 'err' ? 'bg-red-600' : t.k === 'warn' ? 'bg-amber-600' : 'bg-emerald-600')}>{t.m}</div>;
