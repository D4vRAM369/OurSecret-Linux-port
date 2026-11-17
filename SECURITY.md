# Security Policy / Política de seguridad

🌐 **Language / Idioma:** [English](#english) · [Español](#español)

---

<a id="english"></a>

## English

### Project status

This software is **experimental** and **has not undergone an external cryptographic audit**. Do not use it to protect critical information on which your personal or legal safety depends.

### What is covered and what is not

- **Authenticated encryption (Format v3):** **AES-256-GCM** using domain-separated subkeys (**BLAKE2b-MAC**) derived from an **Argon2id** master key (`m = 64 MiB`, `t = 3`, `p = 4`), binding salt and masked length as **AAD**.
- **Undetectability:**
  - `append` mode adds bytes after the end of the carrier file; analysis tools can detect trailing data after EOF in PNG, JPEG, PDF, and ZIP.
  - `lsb` mode uses **±1 matching** and disperses both the 160-bit header and the payload across the entire image, though modern statistical steganalysis can still detect high-density payloads.
- **Untrusted extracted data:** whoever knows the password chooses filenames, subjects, and message bodies. Core enforces **zip-slip** protection, streaming **zip-bomb** limits, and atomic **no-overwrite** (`create_new`); the GUI renders via `textContent` under a strict CSP (`script-src 'self'`), and the CLI escapes ANSI control sequences and Unicode bidirectional overrides (`U+202E`). Keys and passwords are wiped from RAM with `zeroize`.

### Reporting a vulnerability

If you find a security issue (for example, a panic on crafted input, a path traversal on extraction, or a GUI/CSP bypass), please **do not** open a public issue with the exploit directly.

Use the **Security → Advisories → Report a vulnerability** tab on GitHub to report it privately, including:

1. Affected version or commit.
2. Minimal steps to reproduce (without real secrets).
3. Estimated impact.

---

<a id="español"></a>

## Español

### Estado del proyecto

Este software es **experimental** y **no ha pasado una auditoría criptográfica externa**. No lo uses para proteger información crítica de la que dependa tu seguridad personal o legal.

### Qué cubre y qué no

- **Cifrado autenticado (Formato v3):** **AES-256-GCM** con subclaves separadas por dominio (**BLAKE2b-MAC**) derivadas de una clave maestra **Argon2id** (`m = 64 MiB`, `t = 3`, `p = 4`), autenticando sal y longitud enmascarada como **AAD**.
- **Indetectabilidad:**
  - El modo `append` añade bytes al final del archivo; herramientas de análisis detectan datos tras el marcador de fin en PNG, JPEG, PDF y ZIP.
  - El modo `lsb` usa **±1 matching** y dispersa tanto la cabecera de 160 bits como el payload por toda la imagen, pero el estegoanálisis moderno puede detectarlo con cargas altas.
- **Datos extraídos no confiables:** quien conoce la contraseña elige nombres de archivo, asuntos y textos. El núcleo protege frente a *zip-slip*, *zip bombs* y sobrescritura de archivos (`create_new`); la GUI usa `textContent` con CSP estricta (`script-src 'self'`) y la CLI escapa secuencias de escape ANSI y marcas bidireccionales Unicode (`U+202E`). Claves y contraseñas se limpian de memoria con `zeroize`.

### Reportar una vulnerabilidad

Si encuentras un fallo de seguridad (por ejemplo, un *panic* con entradas manipuladas, un escape de ruta al extraer o un problema en la GUI/CSP), por favor **no** abras un *issue* público con el exploit directamente.

Usa la pestaña **Security → Advisories → Report a vulnerability** del repositorio en GitHub para reportarlo de forma privada, incluyendo:

1. Versión o commit afectado.
2. Pasos mínimos para reproducirlo (sin incluir secretos reales).
3. Impacto estimado.
