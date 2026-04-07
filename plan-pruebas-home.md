# Plan de pruebas integral - Nueva Home

## 1) Objetivo

Validar funcionalidad, permisos, navegación, acciones automatizadas y estabilidad general de todo el sitio, con foco en la nueva home y en la sección de pruebas (`/tests/<environment>`), dejando evidencia trazable de cada ejecución.

## 2) Alcance funcional a cubrir

- Home y navegación principal (`/`, header y menús por entorno/realm).
- Login/logout y expiración de sesión.
- Módulos principales:
  - Links
  - Client Info
  - Client Creation
  - Check Clients
  - Clients Activity
  - Terraform Check
  - Tests (listado, ejecución, detalle, descarga y métricas)
  - Deployments
  - User Sessions
  - Change Email
- Manejo de errores y permisos (`403`, accesos por rol).

## 4) Casos de uso para probar la nueva home (y sitio completo)

| ID | Caso de uso | Pasos resumidos | Resultado esperado |
|---|---|---|---|
| HOME-01 | Carga inicial de home | Abrir `/` sin sesión | Se muestra home, menú básico y botón Login |
| HOME-02 | Home con sesión iniciada | Login y volver a `/` | Se muestra usuario y menús protegidos |
| HOME-03 | Navegación por menús | Abrir cada opción de header | Cada opción redirige a su vista correcta |
| HOME-04 | Submenús por entorno | Expandir menús con ambientes | Se listan entornos configurados |
| HOME-05 | Submenús por realm | Abrir Client Info/User Sessions/Change Email | Se listan realms correctos por entorno |
| HOME-06 | UX de sesión expirada | Simular expiración y navegar | Se limpia sesión y pide login sin error 500 |
| SEC-01 | Ruta protegida sin login | Entrar directo a ruta protegida | Redirige a login |
| SEC-02 | Ruta con rol insuficiente | Entrar a ruta restringida | Respuesta `403` |
| LNK-01 | Lista de links por entorno | Ir a `/links/<env>` | Links visibles y válidos |
| CI-01 | Listado de clientes | Ir a `/clientinfo/<env>/<realm>` | Tabla/listado carga correctamente |
| CI-02 | Detalle de cliente | Seleccionar cliente | Detalle consistente, sin campos vacíos inesperados |
| CC-01 | Alta de cliente | Completar formulario y enviar | Confirmación de alta exitosa |
| CC-02 | Alta inválida | Enviar datos inválidos/faltantes | Validaciones visibles y sin 500 |
| CHK-01 | Check clients ejecución | Ejecutar check en entorno | Resultado renderizado con datos |
| ACT-01 | Clients activity | Consultar actividad | Vista carga y datos coherentes |
| TF-01 | Terraform check listado | Abrir `/terraformcheck/<env>` | Vista disponible y ejecutable |
| TF-02 | Terraform check resultado | Ejecutar check | Diff mostrado sin error |
| TST-01 | Listado de corridas de tests | Ir a `/tests/<env>` | Se visualiza historial + opción ejecutar |
| TST-02 | Disparo de tests automatizados | Ejecutar con opción disponible | Se crea nueva corrida y aparece en listado |
| TST-03 | Detalle de corrida | Abrir `/tests/<env>/report/<timestamp>` | Se muestran tests, estados y metadata |
| TST-04 | Evidencia de fallas (imágenes) | Abrir corrida fallida | Imágenes de falla accesibles |
| TST-05 | Descarga de reporte | Descargar JSON de corrida | Archivo descargado con estructura válida |
| TST-06 | Métricas Prometheus | Consultar `/tests/<env>/metrics` | Métricas válidas (passed/failed/total/duration) |
| DEP-01 | Deployments por entorno | Abrir `/deployments/<env>` | Se listan artefactos esperados |
| DEP-02 | Detalle de deployment | Abrir artefacto | Reporte visible con estado consistente |
| SES-01 | User sessions listado | Abrir `/user-sessions/<env>/<realm>` | Sesiones listadas |
| SES-02 | User sessions detalle/acción | Ejecutar acción disponible | Resultado coherente |
| CHM-01 | Change email | Ejecutar cambio de email | Operación exitosa y feedback visible |
| CHM-02 | Change email validación | Forzar error de entrada | Mensaje de validación/negocio correcto |
| ERR-01 | Ruta inexistente | Abrir URL inválida | Manejo de error correcto |
| LOG-01 | Logout completo | Ejecutar logout desde menú usuario | Cierra sesión local e IdP y vuelve a home |

## 5) Prueba completa de acciones planificadas/automatizadas

### Flujo recomendado por entorno

1. Ingresar a `/tests/<environment>`.
2. Ejecutar corrida usando cada `execution_option` disponible.
3. Verificar que la corrida aparece en el listado.
4. Abrir detalle y controlar:
   - cantidad total de tests,
   - tests fallidos/pasados,
   - duración,
   - media de fallas (screenshots) cuando corresponda.
5. Descargar `report.json` y validar formato.
6. Consultar `/tests/<environment>/metrics` y comparar métricas vs reporte descargado.

## 9) Hallazgos relevados durante ejecución (2026-04-07)

### 9.1 Sesión expira rápido

- **Descripción:** la sesión aparenta expirar demasiado rápido durante navegación.
- **Evidencia de log:**

```text
2026-04-07 16:17:07.744 || DEBUG || sherpa-home-main || check_session || Access token expired, attempting to refresh.
2026-04-07 16:17:07.816 || DEBUG || sherpa-home-main || storeTokensInSession || Starting.
2026-04-07 16:17:07.817 || DEBUG || sherpa-home-main || refreshToken || Token refreshed successfully.
```

### 9.2 Error 500 al hacer alta de client

- **Descripción:** al enviar `POST /clientcreation` retorna `500`.
- **Evidencia de log:**

```text
172.18.0.4 - - [07/Apr/2026 16:19:00] "POST /clientcreation HTTP/1.0" 500 -
AttributeError: module 'utils' has no attribute 'logger'. Did you mean: 'Logger'?
TypeError: Logger.error() got an unexpected keyword argument 'exc_info'
```

### 9.3 Desde alta de client no se puede cambiar de módulo

- **Descripción:** al estar en pantalla de alta de cliente no permite navegar a otros módulos.

### 9.4 Clients Activity y Check Clients sin desplegable de realms

- **Descripción:** en `clients_activity` no aparece desplegable de realms.
- **Observación adicional:** comportamiento similar en `check_clients`; queda pendiente confirmar si antes listaba por realms o todo junto.

### 9.5 Links desactualizados en Clients Activity (prod)

- **Descripción:** en `clients_activity` de `prod` hay demoapps desactualizadas.
- **Impacto observado:** algunos links derivan en `Internal Server Error`.

### 9.6 Cambio visual en Terraform Check al replegar

- **Descripción:** al volver a plegar la flecha en `terraform_check`, cambia a color azul.

### 9.7 Pantalla Access Denied sin navegación por módulos

- **Descripción:** al caer en `access denied`, no se puede navegar por los módulos y solo aparece opción de volver a home.

### 9.8 Error de scopes al levantar compose

- **Descripción:** al levantar `docker compose` aparece error de scopes en `master/client_sherpaciamhome.tf` con el scope `email`.
- **Detalle para corregir:** se soluciona quitando `email` de `optional` y agregándolo a `default`.
