import React, { useState } from 'react';
import { api } from '../api.js';
import { card, btn, btn2, inp, th, Campo, useCarga, Cargando, Preguntar } from '../ui.jsx';

const PAGOS = [['efectivo', 'Efectivo'], ['tarjeta', 'Tarjeta'], ['transferencia', 'Transferencia'], ['qr', 'QR']];
const PAGO_TXT = Object.fromEntries(PAGOS);
const KEEP = ['Código de la estancia', 'Iniciales del nombre', 'Documento enmascarado (últimos 3 caracteres)', 'Nacionalidad (uso estadístico)', 'Habitación y fechas de la estancia',
  'Monto y método de pago (obligación contable/fiscal)', 'Últimos 4 dígitos de la tarjeta (el pago es un registro inmutable)'];
const DROP = ['Nombre completo (queda reducido a iniciales)', 'Documento completo', 'Teléfono', 'Correo electrónico', 'Fecha de nacimiento'];
const ESTADO = { reservada: ['Reservada', 'bg-sky-100 text-sky-800 dark:bg-sky-900/40 dark:text-sky-300'], hospedada: ['Hospedado', 'bg-emerald-100 text-emerald-800 dark:bg-emerald-900/40 dark:text-emerald-300'],
  finalizada: ['Finalizada', 'bg-amber-100 text-amber-800 dark:bg-amber-900/40 dark:text-amber-300'], anulada: ['Anulada', 'bg-red-100 text-red-800 dark:bg-red-900/40 dark:text-red-300'] };
const hoy = () => new Date().toISOString().slice(0, 10);
const blanco = () => ({ nombre: '', documento_tipo: 'CI', documento: '', nacionalidad: 'Boliviana', telefono: '', email: '', fecha_nacimiento: '', habitacion: '', ingreso: hoy(), salida: '', metodo_pago: 'efectivo', tarjeta_ultimos4: '', monto: '', consentimiento: false });

export default function Huespedes({ c }) {
  const { d, err, recargar } = useCarga(() => api.get('/huespedes'));
  const hab = useCarga(() => (c.can('reservas', 'leer') ? api.get('/panel') : Promise.resolve({ habitaciones: [] })));
  const [f, setF] = useState(blanco), [anular, setAnular] = useState(null), [ocupado, setOcupado] = useState(false);
  const set = (k, v) => setF({ ...f, [k]: v });
  const crear = c.can('expedientes_huespedes', 'crear'), modif = c.can('expedientes_huespedes', 'modificar'), anula = c.can('reservas', 'modificar');
  const auditor = c.me.rol === 'Auditor';
  if (!d) return <Cargando err={err} />;

  const registrar = async () => {
    if (!f.nombre.trim() || !f.documento.trim() || !f.habitacion || !f.salida || !f.monto) return c.toast('Complete los campos obligatorios (*).', 'warn');
    if (!f.consentimiento) return c.toast('Se requiere el consentimiento para el tratamiento de datos.', 'warn');
    setOcupado(true);
    const r = await c.act(() => api.post('/huespedes', { ...f, monto: Number(f.monto), tarjeta_ultimos4: f.metodo_pago === 'tarjeta' ? f.tarjeta_ultimos4 : undefined }));
    setOcupado(false);
    if (r) { c.toast(`${r.estado === 'hospedada' ? 'Check-in' : 'Reserva'} ${r.codigo} registrado en la habitación ${r.habitacion}.`); setF(blanco()); recargar(); hab.recargar(); }
  };
  const accion = async (g, ruta, ok) => { if (await c.act(() => api.post(`/huespedes/${g.codigo}/${ruta}`), ok)) { recargar(); hab.recargar(); } };
  const confirmarAnular = async (motivo) => {
    const r = await c.act(() => api.post(`/huespedes/${anular.codigo}/anular`, { motivo }), `Estancia ${anular.codigo} anulada.`);
    if (r) { setAnular(null); recargar(); hab.recargar(); }
  };
  const L = Campo;
  return <div className="space-y-4">
    {crear ? <div className={card}><h3 className="font-semibold mb-2">Registro de huésped (check-in o reserva)</h3>
      <div className="grid sm:grid-cols-3 gap-2">
        <L t="Nombre completo *"><input className={inp} value={f.nombre} maxLength={100} onChange={(e) => set('nombre', e.target.value)} /></L>
        <L t="Tipo de documento"><select className={inp} value={f.documento_tipo} onChange={(e) => set('documento_tipo', e.target.value)}><option value="CI">CI</option><option value="pasaporte">Pasaporte</option><option value="otro">Otro</option></select></L>
        <L t="Documento de identidad *"><input className={inp} value={f.documento} maxLength={30} onChange={(e) => set('documento', e.target.value)} /></L>
        <L t="Nacionalidad"><input className={inp} value={f.nacionalidad} onChange={(e) => set('nacionalidad', e.target.value)} /></L>
        <L t="Teléfono"><input className={inp} value={f.telefono} maxLength={30} onChange={(e) => set('telefono', e.target.value)} /></L>
        <L t="Correo electrónico"><input type="email" className={inp} value={f.email} maxLength={120} onChange={(e) => set('email', e.target.value)} /></L>
        <L t="Fecha de nacimiento"><input type="date" className={inp} value={f.fecha_nacimiento} onChange={(e) => set('fecha_nacimiento', e.target.value)} /></L>
        <L t="Habitación *"><select className={inp} value={f.habitacion} onChange={(e) => set('habitacion', e.target.value)}><option value="">Seleccione…</option>
          {(hab.d?.habitaciones || []).map((h) => <option key={h.numero} value={h.numero}>{h.numero} · {h.tipo} · Bs {h.tarifa_noche}/noche · {h.estado}</option>)}</select></L>
        <L t="Ingreso (futuro = reserva)"><input type="date" className={inp} value={f.ingreso} onChange={(e) => set('ingreso', e.target.value)} /></L>
        <L t="Salida prevista *"><input type="date" className={inp} value={f.salida} min={f.ingreso} onChange={(e) => set('salida', e.target.value)} /></L>
        <L t="Forma de pago *"><select className={inp} value={f.metodo_pago} onChange={(e) => set('metodo_pago', e.target.value)}>{PAGOS.map(([k, v]) => <option key={k} value={k}>{v}</option>)}</select></L>
        {f.metodo_pago === 'tarjeta' && <L t="Últimos 4 dígitos *"><input className={inp} maxLength={4} inputMode="numeric" value={f.tarjeta_ultimos4} onChange={(e) => set('tarjeta_ultimos4', e.target.value.replace(/\D/g, ''))} /></L>}
        <L t="Monto total (Bs) *"><input type="number" min="0" step="0.01" className={inp} value={f.monto} onChange={(e) => set('monto', e.target.value)} /></L>
      </div>
      <label className="flex items-center gap-2 text-sm mt-3"><input type="checkbox" checked={f.consentimiento} onChange={(e) => set('consentimiento', e.target.checked)} />El huésped consiente el tratamiento de sus datos y su depuración al finalizar la estancia.</label>
      <button className={btn + ' mt-3'} onClick={registrar} disabled={ocupado}>Registrar huésped</button>
      <p className="text-xs text-slate-500 mt-2">Nunca se guarda el número completo de la tarjeta: solo los últimos 4 dígitos. Documento, teléfono, correo y nacimiento se almacenan cifrados (AES-256-GCM).</p></div>
      : <div className={card + ' text-sm text-slate-500'}>Su rol ({c.me.rol}) tiene acceso de solo lectura: datos personales enmascarados y sin registro de huéspedes.</div>}
    <div className="grid md:grid-cols-2 gap-4">
      <div className={card}><h4 className="font-semibold mb-2 text-emerald-600 dark:text-emerald-400">✔ Se conserva al finalizar la estancia</h4>{KEEP.map((k) => <div key={k} className="text-sm py-0.5">• {k}</div>)}</div>
      <div className={card}><h4 className="font-semibold mb-2 text-red-600 dark:text-red-400">🗑 Se depura al hacer check-out</h4>{DROP.map((k) => <div key={k} className="text-sm py-0.5">• {k}</div>)}</div></div>
    <div className={card + ' overflow-x-auto'}><div className="flex justify-between mb-2"><h3 className="font-semibold">Estancias</h3><button className={btn2} onClick={recargar}>Actualizar</button></div>
      <table className="w-full text-sm"><thead><tr>{['Código', 'Huésped', 'Documento', 'Contacto', 'Hab.', 'Estancia', 'Pago', 'Estado', ''].map((t) => <th key={t} className={th}>{t}</th>)}</tr></thead><tbody>
        {d.huespedes.map((g) => {
          const vivo = g.estado === 'reservada' || g.estado === 'hospedada';
          const ajena = !auditor && !g.propia && c.me.rol === 'Recepcionista';
          const dato = (v) => (v ? v : auditor ? '••••••' : '— depurado —');
          return <tr key={g.codigo} className="border-t border-slate-100 dark:border-slate-800">
            <td className="px-3 py-2 font-mono">{g.codigo}</td><td className="px-3">{g.nombre || '— sin acceso —'}</td>
            <td className="px-3">{g.documento || g.documento_enmascarado}</td>
            <td className="px-3 text-xs">{dato(g.telefono)}<br />{dato(g.email)}</td><td className="px-3">{g.habitacion}</td>
            <td className="px-3 whitespace-nowrap">{g.ingreso} → {g.salida}</td>
            <td className="px-3">{g.pago ? <>{PAGO_TXT[g.pago.metodo]}{g.pago.tarjeta_ultimos4 && ' ••' + g.pago.tarjeta_ultimos4}<br /><span className="text-xs text-slate-500">Bs {g.pago.total}</span></> : '—'}</td>
            <td className="px-3"><span className={'px-2 py-0.5 rounded-full text-xs ' + ESTADO[g.estado][1]}>{ESTADO[g.estado][0]}</span></td>
            <td className="px-3 py-2"><div className="flex flex-wrap gap-1.5">
              {vivo && modif && g.estado === 'reservada' && <button className={btn2} disabled={ajena} title={ajena ? 'Estancia registrada por otro recepcionista' : ''} onClick={() => accion(g, 'checkin', `Check-in de ${g.codigo} realizado.`)}>Check-in</button>}
              {vivo && modif && g.estado === 'hospedada' && <button className={btn2} disabled={ajena} title={ajena ? 'Estancia registrada por otro recepcionista' : ''} onClick={() => accion(g, 'checkout', `Check-out de ${g.codigo}: datos personales depurados.`)}>Check-out</button>}
              {vivo && anula && <button className={btn2} disabled={ajena} title="Alto riesgo: pide 2FA" onClick={() => setAnular(g)}>Anular</button>}
              {!vivo && g.datos_depurados && <span className="text-xs text-slate-500">Datos depurados</span>}
              {auditor && g.registrada_por && <span className="text-xs text-slate-500">por {g.registrada_por}</span>}
            </div></td></tr>;
        })}
        {d.huespedes.length === 0 && <tr><td colSpan="9" className="px-3 py-4 text-slate-500">Aún no hay estancias registradas.</td></tr>}
      </tbody></table>
      {c.me.rol === 'Recepcionista' && <p className="text-xs text-slate-500 mt-2">Un recepcionista solo opera sobre las estancias que él mismo registró (contexto persona/objeto). Para cambios de turno, solicite la acción a un Administrador.</p>}
    </div>
    {anular && <Preguntar titulo={'Anular ' + anular.codigo} descripcion="Operación de alto riesgo: se pedirá el segundo factor. Los datos personales se depuran si no hay otra estancia vigente." etiqueta="Motivo de la anulación (mínimo 5 caracteres)" minimo={5} boton="Anular estancia" onOk={confirmarAnular} onClose={() => setAnular(null)} />}
  </div>;
}
