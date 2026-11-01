import React, { useEffect, useState } from 'react';
import { api } from './api.js';
import { card, btn, btn2, inp, Modal, Campo } from './ui.jsx';

const ErrorBox = ({ children }) => <div className="rounded-lg bg-red-100 dark:bg-red-900/40 text-red-700 dark:text-red-300 text-sm p-3">{children}</div>;

const Fondo = ({ children }) => <div className="min-h-screen flex items-center justify-center p-4 bg-gradient-to-br from-indigo-950 via-slate-900 to-slate-950">{children}</div>;

/* ---------------------------------------------------------------- LOGIN (P2: mensaje genérico; el bloqueo lo decide el servidor) */
export function Login({ onEntrar, dark, setDark }) {
  const [u, setU] = useState(''), [p, setP] = useState(''), [ver, setVer] = useState(false);
  const [err, setErr] = useState(''), [hasta, setHasta] = useState(0), [ahora, setAhora] = useState(Date.now()), [ocupado, setOcupado] = useState(false);
  useEffect(() => { const t = setInterval(() => setAhora(Date.now()), 500); return () => clearInterval(t); }, []);
  const resta = Math.max(0, Math.ceil((hasta - ahora) / 1000));

  const enviar = async (e) => {
    e.preventDefault();
    if (resta > 0 || ocupado) return;
    setOcupado(true);
    try {
      await api.post('/auth/login', { username: u.trim(), password: p });
      setP(''); setErr('');
      await onEntrar();
    } catch (x) {
      setErr(x.message);
      if (x.status === 429 && x.data.reintentar_en_s) { setHasta(Date.now() + x.data.reintentar_en_s * 1000); setAhora(Date.now()); }
    } finally { setOcupado(false); }
  };
  return <Fondo><div className={card + ' w-full max-w-sm'}>
    <div className="flex justify-between items-start">
      <div><div className="text-3xl">🏨</div><h1 className="text-xl font-bold mt-1">HotelSec</h1><p className="text-sm text-slate-500">Acceso al sistema de gestión hotelera</p></div>
      <button className={btn2} onClick={() => setDark(!dark)} aria-label="Cambiar tema">{dark ? '☀️' : '🌙'}</button>
    </div>
    <form onSubmit={enviar} className="mt-5 space-y-3">
      <Campo t="Usuario"><input className={inp} value={u} onChange={(e) => setU(e.target.value)} autoComplete="username" disabled={resta > 0} maxLength={64} /></Campo>
      <Campo t="Contraseña"><div className="relative">
        <input type={ver ? 'text' : 'password'} className={inp + ' pr-10'} value={p} onChange={(e) => setP(e.target.value)} disabled={resta > 0} autoComplete="current-password" maxLength={256} />
        <button type="button" onClick={() => setVer(!ver)} aria-label={ver ? 'Ocultar contraseña' : 'Mostrar contraseña'} className="absolute inset-y-0 right-0 px-3 text-slate-500">{ver ? '🙈' : '👁️'}</button>
      </div></Campo>
      {resta > 0
        ? <ErrorBox>🔒 Acceso bloqueado por intentos fallidos. Reintente en <b>{resta}s</b>.</ErrorBox>
        : err && <ErrorBox>{err}</ErrorBox>}
      <button className={btn + ' w-full py-2'} disabled={resta > 0 || !u || !p || ocupado}>{ocupado ? 'Verificando…' : 'Iniciar sesión'}</button>
    </form>
  </div></Fondo>;
}

/* ---------------------------------------------------------------- CAMBIO DE CONTRASEÑA OBLIGATORIO (primer ingreso) */
export function CambiarPassword({ minimo, onListo, onSalir }) {
  const [a, setA] = useState(''), [n, setN] = useState(''), [n2, setN2] = useState(''), [err, setErr] = useState(''), [ocupado, setOcupado] = useState(false);
  const enviar = async (e) => {
    e.preventDefault();
    if (n !== n2) return setErr('Las contraseñas nuevas no coinciden');
    setOcupado(true);
    try { await api.post('/auth/cambiar-password', { actual: a, nueva: n }); await onListo(); }
    catch (x) { setErr(x.message); } finally { setOcupado(false); }
  };
  return <Fondo><div className={card + ' w-full max-w-sm'}>
    <h1 className="text-lg font-bold">Cambie su contraseña</h1>
    <p className="text-sm text-slate-500 mt-1">Por seguridad debe reemplazar la contraseña temporal antes de continuar. Mínimo {minimo} caracteres, sin incluir su usuario.</p>
    <form onSubmit={enviar} className="mt-4 space-y-3">
      <Campo t="Contraseña actual"><input type="password" className={inp} value={a} onChange={(e) => setA(e.target.value)} autoComplete="current-password" /></Campo>
      <Campo t="Contraseña nueva"><input type="password" className={inp} value={n} onChange={(e) => setN(e.target.value)} autoComplete="new-password" /></Campo>
      <Campo t="Repita la contraseña nueva"><input type="password" className={inp} value={n2} onChange={(e) => setN2(e.target.value)} autoComplete="new-password" /></Campo>
      {err && <ErrorBox>{err}</ErrorBox>}
      <button className={btn + ' w-full py-2'} disabled={!a || !n || !n2 || ocupado}>Guardar contraseña</button>
      <button type="button" className={btn2 + ' w-full'} onClick={onSalir}>Cerrar sesión</button>
    </form>
  </div></Fondo>;
}

/* ---------------------------------------------------------------- 2FA: verificar un código o configurar el autenticador */
export function MfaModal({ modo, operacion, onListo, onCancelar }) {
  const [paso, setPaso] = useState(modo === 'enrolar' ? 'clave' : 'codigo');
  const [pass, setPass] = useState(''), [codigo, setCodigo] = useState(''), [dato, setDato] = useState(null);
  const [err, setErr] = useState(''), [ocupado, setOcupado] = useState(false);

  const iniciar = async () => {
    setOcupado(true); setErr('');
    try { setDato(await api.post('/auth/2fa/iniciar', { password: pass })); setPass(''); setPaso('codigo'); }
    catch (x) { setErr(x.message); } finally { setOcupado(false); }
  };
  const confirmar = async () => {
    setOcupado(true); setErr('');
    try {
      await api.post(dato ? '/auth/2fa/activar' : '/auth/2fa/verificar', { codigo });
      setDato(null); await onListo();
    } catch (x) { setErr(x.message + (x.data.reintentar_en_s ? ` (${x.data.reintentar_en_s}s)` : '')); setCodigo(''); }
    finally { setOcupado(false); }
  };
  return <Modal title="🔐 Segundo factor de autenticación (2FA)" onClose={onCancelar}>
    {operacion && <p className="text-sm text-slate-500 mb-2">Operación de alto riesgo: <b>{operacion}</b>.</p>}
    {paso === 'clave' && <>
      <p className="text-sm text-slate-500">Esta operación exige segundo factor y aún no lo tiene configurado. Confirme su contraseña para generar el código QR de su aplicación autenticadora (Google Authenticator, Authy, etc.).</p>
      <input type="password" className={inp + ' mt-3'} placeholder="Su contraseña actual" value={pass} onChange={(e) => setPass(e.target.value)} autoComplete="current-password" onKeyDown={(e) => e.key === 'Enter' && pass && iniciar()} />
      {err && <p className="text-sm text-red-500 mt-2">{err}</p>}
      <button className={btn + ' w-full mt-3'} disabled={!pass || ocupado} onClick={iniciar}>Generar código QR</button>
    </>}
    {paso === 'codigo' && <>
      {dato && <div className="text-center mb-2">
        <p className="text-sm text-slate-500">Escanee el QR con su aplicación y escriba el primer código que muestre.</p>
        <img src={dato.qr} alt="Código QR para configurar el autenticador" className="mx-auto my-2 bg-white rounded" width="220" height="220" />
        <p className="text-xs text-slate-500">¿No puede escanear? Clave manual:</p><code className="text-xs break-all select-all">{dato.secreto}</code>
      </div>}
      {!dato && <p className="text-sm text-slate-500">Ingrese el código de 6 dígitos de su aplicación autenticadora.</p>}
      <input autoFocus inputMode="numeric" autoComplete="one-time-code" maxLength={6} value={codigo} onChange={(e) => setCodigo(e.target.value.replace(/\D/g, ''))}
        onKeyDown={(e) => e.key === 'Enter' && codigo.length === 6 && confirmar()}
        className={inp + ' mt-3 text-center text-2xl tracking-[0.5em] font-mono'} placeholder="••••••" />
      {err && <p className="text-sm text-red-500 mt-2">{err}</p>}
      <button className={btn + ' w-full mt-3'} disabled={codigo.length !== 6 || ocupado} onClick={confirmar}>{dato ? 'Activar 2FA' : 'Verificar'}</button>
    </>}
  </Modal>;
}
