# HotelSec · Gestión hotelera segura

Sistema de gestión hotelera con **Node.js + Express + PostgreSQL** y un frontend React **precompilado** (sin CDN, sin Babel en el navegador), diseñado para funcionar bajo una **CSP estricta** (`script-src 'self'; style-src 'self'`).

La seguridad no depende del navegador: toda decisión de acceso se evalúa en el servidor con la función `evaluar_acceso` de la base de datos, la aplicación entra a PostgreSQL con un rol sin privilegios y asume el rol del usuario (`SET LOCAL ROLE`) en cada transacción.

---

## 1. Puesta en marcha

Requisitos: Node.js ≥ 18, PostgreSQL ≥ 13 (con la extensión `pgcrypto`, y `btree_gist` para el solape de reservas), y `pg_dump` si va a usar `npm run respaldo`.

```bash
npm install                      # genera package-lock.json (el del Paso 1 quedó obsoleto); en producción: npm install --omit=dev
cp .env.example .env             # complete los valores
npm run gen:key                  # genera MASTER_KEY → péguela en .env
npm run setup:db                 # esquema + roles + ajustes (db/01 … db/04)
npm start                        # http://localhost:3000
```

* `npm run setup:db -- --reset --yes` **borra todo** y recrea la base desde cero (útil para desarrollo y para los smoke tests).
* La carpeta `public/` **ya está compilada**. Solo necesita `npm run build:front` si modifica algo de `frontend/` (instala las dependencias de desarrollo: React, esbuild, Tailwind).
* **Guarde `MASTER_KEY` fuera del servidor** (gestor de secretos). Si se pierde, los datos cifrados (huéspedes, secretos 2FA, respaldos, exportaciones) no se pueden recuperar.

### Usuarios de demostración (semilla)

| Usuario | Contraseña | Rol | Estado |
|---|---|---|---|
| `admin` | `Admin#2026` | Administrador | activa |
| `recepcion` | `Recep#2026` | Recepcionista | activa |
| `auditor` | `Audit#2026` | Auditor | activa |
| `jperez` | `Temp#2026` | Recepcionista | suspendida |
| `mvargas` | `Temp#2026` | Auditor | revocada |

> ⚠️ Son credenciales públicas de demostración. **Antes de cualquier uso real** cambie sus contraseñas (o revóquelas) y cree identidades propias. La pantalla de login ya no las muestra.

### Primer recorrido sugerido

1. Entre como `admin`. En el panel pulse **Configurar segundo factor**: confirme su contraseña, escanee el QR con una app autenticadora y escriba el primer código.
2. En **Identidades** cree un usuario: nace *suspendida*, con una contraseña temporal aleatoria que se muestra **una sola vez**. Dele **Alta** (pide 2FA). Al entrar por primera vez esa persona deberá cambiar la contraseña.
3. En **Huéspedes** registre un check-in; haga el check-out y compruebe que los datos personales quedan depurados.
4. En **Auditoría** pulse *Verificar integridad* y luego *Intentar editar un registro* (lo rechaza la propia base de datos).
5. En **Políticas** ejecute la verificación de controles: cada regla se prueba contra la BD real.

---

## 2. Cómo funciona el segundo factor en la interfaz

El servidor decide qué operaciones exigen 2FA (tabla `operacion_sistema`). El frontend no lo adivina: intenta la operación y, si recibe `MFA_REQUERIDO` o `MFA_NO_CONFIGURADO`, abre el asistente (código de 6 dígitos, o alta del autenticador con QR), y **reintenta una sola vez**. El código TOTP vale unos minutos (`mfa_vigencia_minutos`) y no se puede reutilizar.

Operaciones con 2FA: crear identidad, **cualquier cambio de estado** (alta, suspensión, revocación), solicitar/aprobar cambio de rol, modificar la matriz, exportar la bitácora, anular reservas. La degradación segura bloquea esas mismas operaciones.

---

## 3. Mapa pantalla ↔ API

| Pantalla | Rutas principales | Quién |
|---|---|---|
| Login / cambio de contraseña | `POST /api/auth/login`, `GET /api/auth/yo`, `POST /api/auth/cambiar-password`, `/api/auth/2fa/{iniciar,activar,verificar}` | todos |
| Panel | `GET /api/panel`, `POST /api/habitaciones/:n/liberar` | todos (eventos y alertas: Admin y Auditor) |
| Huéspedes | `GET/POST /api/huespedes`, `POST /:codigo/{checkin,checkout,anular}` | Admin, Recepción (crear/operar); Auditor solo lectura enmascarada |
| Identidades | `/api/usuarios` (alta, `/:c/estado`, `/:c/cambio-rol`, `/solicitudes-rol`, `/:c/historial`) | Administrador |
| Autorización | `GET/PUT /api/matriz`, `POST /api/matriz/evaluar`, `GET /api/matriz/usuarios` | ver: Admin y Auditor · editar: Admin |
| Auditoría | `GET /api/bitacora`, `/verificar`, `/intento-edicion`, `/exportar` | Admin y Auditor |
| Incidentes | `/api/incidentes`, `/api/emergencia`, `/api/respaldos` | ver: Admin y Auditor · gestionar: Admin · revisar emergencias: Auditor |
| Políticas | `GET /api/politicas`, `POST /api/politicas/verificar` | todos (verificar: Admin y Auditor) |

Cada archivo de `src/routes/` se monta solo en `/api/<nombre>`. El menú del frontend se construye con los permisos que devuelve `/api/auth/yo`, pero **eso es solo comodidad**: el servidor vuelve a evaluar cada petición.

Cambios de este paso en el backend: `POST /api/huespedes/:codigo/checkin` (pasar una reserva a hospedada), `POST /api/habitaciones/:numero/liberar` (limpieza → libre; sin esto las habitaciones quedaban en limpieza para siempre) y `GET /api/matriz/usuarios` (el Auditor no puede leer la tabla de usuarios, pero el simulador necesita la lista).

---

## 4. Seguridad del frontend

* Bundle propio (`public/app.js`), CSS propio (`public/app.css`) y `theme.js`: **ningún recurso externo**, sin scripts ni estilos en línea, sin `eval`.
* Sesión en cookie `httpOnly` + `SameSite=Strict` (+ `Secure` en producción). El JavaScript nunca ve el token; no se guarda nada sensible en `localStorage` (solo la preferencia de tema).
* Defensa CSRF: comprobación de `Origin` y cabecera `X-Requested-With: hotelsec` en toda petición que modifica datos.
* React escapa todo lo que se muestra (no se usa `dangerouslySetInnerHTML`).
* `npm run check:front` verifica automáticamente que `public/` cumple la CSP.

---

## 5. Pruebas

Los smoke tests necesitan el servidor levantado y una BD **recién creada** (`npm run setup:db -- --reset --yes`):

```bash
npm run smoke:1     # Paso 1: login, sesiones, bloqueo, 2FA
npm run smoke:2     # Paso 2: identidades, huéspedes, bitácora, incidentes, respaldos
npm run smoke:3     # Paso 3: frontend + CSP, check-in de reserva, liberar habitación, simulador
npm run check:front # cumplimiento de la CSP del frontend compilado
```

---

## 6. Limitaciones conocidas (léalas antes de presentarlo o ponerlo en producción)

1. **La cuenta de emergencia no tiene inicio de sesión propio.** Está implementado el flujo auditable (habilitar con incidente vigente y motivo, cerrar el uso, revisión del Auditor), pero no se puede iniciar sesión con las credenciales de `breakglass-01`; su hash en la BD no se usa. Hacerlo requiere decidir qué identidad y qué rol de BD asume esa sesión (el esquema asocia las sesiones a `usuario`).
2. **El nombre del huésped se guarda en claro** (`nombre_completo`); solo documento, teléfono, correo y nacimiento van cifrados. Al depurar queda como iniciales («C. M. Q.»). Es una limitación del diseño de la tabla.
3. **Un recepcionista no puede hacer check-in, check-out ni anular una estancia registrada por otro** (regla persona/objeto del esquema). Complica el cambio de turno; el Administrador sí puede. La interfaz lo avisa.
4. **La restauración solo se registra, no se ejecuta.** La API exige respaldo verificado, incidente vigente y la autorización de otro administrador con su código 2FA; el `pg_restore` real se hace a mano en el servidor.
5. **Los eventos del panel solo los ven Administrador y Auditor** (la matriz no da lectura de bitácora a recepción).
6. **«Se elimina el dígito de la tarjeta» no es posible**: la tabla `pago` es inmutable y conserva los últimos 4 dígitos. El texto del frontend se corrigió.
7. **Sin sesiones múltiples controladas por el usuario**: no hay pantalla para ver/cerrar las sesiones propias (la BD sí las registra y las revoca al cambiar contraseña, estado o rol).
8. **Estado de pruebas:** el frontend se probó en un navegador real (Chromium) contra un servidor simulado con las mismas formas de respuesta que la API y con la misma CSP. Las rutas añadidas en el Paso 3 y todo el backend **no se ejecutaron contra una PostgreSQL real** en el entorno donde se escribieron; están verificadas sintácticamente y con `smoke:3`, que debe correr usted. Si algún smoke test falla, el mensaje indica la ruta.

## 7. Lista de verificación para producción

- [ ] HTTPS delante (nginx/Cloudflare) y `COOKIE_SECURE=true`, `TRUST_PROXY=1`, `APP_ORIGIN=https://su-dominio`.
- [ ] `NODE_ENV=production` (la app se niega a arrancar si se conecta como superusuario de BD).
- [ ] Contraseñas de demostración cambiadas o identidades revocadas.
- [ ] `MASTER_KEY` y `APP_DB_PASSWORD` en un gestor de secretos; copia de `MASTER_KEY` guardada aparte.
- [ ] Respaldos programados (`npm run respaldo`) y una prueba de restauración en otro servidor.
- [ ] Cada administrador con su 2FA configurado (la restauración exige a un segundo administrador).
