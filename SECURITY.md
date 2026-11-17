# Política de seguridad

## Estado del proyecto

Este software es **experimental** y **no ha pasado una auditoría criptográfica externa**. No lo uses para proteger información crítica de la que dependa tu seguridad personal o legal.

## Qué cubre y qué no

- **Cifrado autenticado:** AES-256-GCM con clave derivada mediante Argon2id (`m = 64 MiB`, `t = 3`, `p = 4`).
- **Indetectabilidad:**
  - El modo `append` añade bytes al final del archivo; herramientas de análisis detectan datos tras el marcador de fin en PNG, JPEG, PDF y ZIP.
  - El modo `lsb` usa ±1 matching y dispersión dependiente de la clave, pero el estegoanálisis moderno puede detectarlo con cargas altas.
- **Datos extraídos no confiables:** quien conoce la contraseña elige nombres de archivo, asuntos y textos. El núcleo protege frente a *zip-slip*, *zip bombs* y sobrescritura de archivos; la GUI usa `textContent` con CSP estricta y la CLI escapa secuencias de escape ANSI y marcas bidireccionales Unicode.

## Reportar una vulnerabilidad

Si encuentras un fallo de seguridad (por ejemplo, un *panic* con entradas manipuladas, un escape de ruta al extraer o un problema en la GUI/CSP), por favor **no** abras un *issue* público con el exploit directamente.

Usa la pestaña **Security → Advisories → Report a vulnerability** del repositorio en GitHub para reportarlo de forma privada, incluyendo:

1. Versión o commit afectado.
2. Pasos mínimos para reproducirlo (sin incluir secretos reales).
3. Impacto estimado.
