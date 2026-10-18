# 01 · Informe de políticas de seguridad

> **Pregunta que responde:** ¿Qué protegemos y bajo qué reglas?
> **Archivo de entrega:** `P1_Politicas_grupo4.tex` + `P1_Politicas_grupo4.pdf`
> **Peso en la nota:** 18 %
> **Extensión:** 8 a 12 páginas de contenido (sin contar portada, índice ni anexos).

## Propósito
Documento dirigido a la **gerencia de Verdeazul** (Marcela Quesada Ureña). **No es un manual técnico**: es el marco que después justifica cada decisión de control de acceso (Entregable 2), cada celda de la matriz (Entregable 3) y cada tecnología (Entregable 4). Si una decisión posterior no se puede rastrear hasta una política o amenaza de este informe, falta algo aquí.

## Qué hay que desarrollar

### 1. Alcance y activos
- Qué cubre la política (plataforma, personas, procesos, período de vigencia) y qué queda fuera.
- **Inventario de activos de información** de Verdeazul, por ejemplo: mediciones de biomasa, períodos de medición, certificados de carbono, catálogo de fincas, datos personales de dueños y empleados, bitácora/registro de auditoría, enmiendas, credenciales, evidencia de campo.
- **Clasificación por sensibilidad** (p. ej. Público / Interno / Confidencial / Restringido) con el criterio de cada nivel y quién es el propietario del activo.

### 2. La tríada aplicada al negocio
- Qué significa **confidencialidad**, **integridad** y **disponibilidad** *en Verdeazul* (no la definición de libro).
- Cuál de las tres **pesa más y por qué**. Pista de la carta: un dato inflado es fraude, una medición se modificó después de aprobada, un certificado se emitió dos veces → integridad y trazabilidad.
- Cómo se ordenan las otras dos (confidencialidad entre dueños de finca que son competencia; disponibilidad para técnicos de campo).

### 3. Modelo de amenazas
- **Quién** querría atacar el sistema, **con qué motivo** y **qué podría lograr**.
- Debe incluir **al menos una amenaza interna**. La carta da material de sobra:
  - Técnico que infla mediciones (fraude).
  - Edición silenciosa de una medición ya aprobada.
  - Doble emisión de certificado sobre la misma hectárea.
  - Empleado con permiso legítimo que consulta cientos de fincas antes de irse a la competencia.
  - Dueño de finca que intenta ver datos de un competidor.
- Amenazas externas: robo de credenciales, acceso directo a objetos (IDOR), alteración de bitácora, etc.
- Presentarlo en tabla (actor, motivación, vector, activo afectado, impacto, probabilidad).

### 4. Marco regulatorio
- Obligaciones legales que aplican al giro del cliente. **Mínimo: Ley 8968** de Protección de la Persona frente al Tratamiento de sus Datos Personales (y su reglamento; PRODHAB).
- Otras a considerar: requisitos de trazabilidad de 10 años exigidos por auditores/estándares europeos de carbono, normativa de firma digital (Ley 8454), etc.
- Cada obligación se **traduce en una regla operativa** concreta (no solo se cita).

### 5. Políticas de cuentas y accesos
- **Alta, baja y cambio de puesto** (quién la solicita, quién la aprueba, plazos).
- **Revisión periódica de permisos** (frecuencia y responsable).
- **Bitácora:** qué se registra y **por cuánto tiempo** (conectar con los 10 años de trazabilidad).

### 6. Política de contraseñas y autenticación
- Coherente con lo visto en clase (longitud, listas de contraseñas comprometidas, sin rotación forzada arbitraria, MFA, FIDO2/WebAuthn, bloqueo por intentos, recuperación de cuenta).
- Diferenciar por perfil de usuario (técnico de campo vs. verificador vs. administrador vs. auditor vs. dueño de finca).

### Anexo obligatorio
- **Minuta de la reunión con el cliente** (consultas enviadas a `a.vargas@itcr.ac.cr`). Lo respondido pasa a formar parte del enunciado del grupo.

## Checklist de rúbrica (Excelente)
- [ ] Políticas **específicas de Verdeazul**, no genéricas.
- [ ] Al menos una **amenaza interna**.
- [ ] Marco legal **pertinente al giro** (Ley 8968 como mínimo).
- [ ] Extensión 8–12 páginas.
- [ ] Portada completa, referencias APA, minuta en anexo.

## Estructura de archivos

```text
01InformePoliticas/
├── P1_Politicas_grupo4.tex   ← preámbulo + portada + estructura del documento
├── .latexmkrc                ← ejecuta makeglossaries
├── referencias.bib
├── img/TUlogo.png
└── sec/
    ├── 00resumen.tex
    ├── 01alcanceactivos.tex
    ├── 02triada.tex
    ├── 03amenazas.tex
    ├── 04marcolegal.tex
    ├── 05cuentasaccesos.tex
    ├── 06contrasenas.tex
    └── A1minuta.tex
```
