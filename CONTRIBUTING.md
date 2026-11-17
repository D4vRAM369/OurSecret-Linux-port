# Contributing / Contribuir a OurSecret Linux

🌐 **Language / Idioma:** [English](#english) · [Español](#español)

---

<a id="english"></a>

## English

Thank you for your interest in improving this project! Before opening a Pull Request, please keep these essential rules in mind.

### Clean-room rule (mandatory)

This project is a **clean-room** reimplementation of OurSecret (Windows, SecureKit.net).

- We **do not** accept disassembled, decompiled, or copied code from the original binary (`OurSecret.exe`).
- We **do not** accept changes aimed at making the container format compatible with the original OurSecret.
- Core/CLI source comments and internal developer docs are kept in **Spanish** (while public user-facing UI/README support both English and Spanish).

### Format stability

- The current **Format v3** intentionally omits magic headers and version bytes (so files reveal nothing without the password).
- Do not change Argon2id parameters, BLAKE2b subkey derivation, or the LSB permutation (`crypto::permutation`) without discussing it in an issue first — doing so breaks reading existing files.
- `crypto::tests::format_is_pinned` protects these golden test vectors.

### Local checks before opening a PR

CI requires all of these to pass with zero warnings:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node --check gui/src/main.js
node --check gui/src/i18n.js
```

---

<a id="español"></a>

## Español

¡Gracias por tu interés en mejorar este proyecto! Antes de abrir un *Pull Request*, ten en cuenta estas reglas esenciales.

### Regla *clean-room* (obligatoria)

Este proyecto es una reimplementación **clean-room** de OurSecret (Windows, SecureKit.net).

- **No** aceptamos código desensamblado, descompilado ni copiado del binario original (`OurSecret.exe`).
- **No** aceptamos cambios cuyo objetivo sea hacer el formato compatible con el del OurSecret original.
- El código interno, comentarios y documentación técnica del núcleo se mantienen en **español** (la interfaz y portada pública soportan inglés y español).

### Estabilidad del formato

- El **Formato v3** actual no incluye cabecera mágica ni número de versión a propósito (para no delatar su presencia sin la contraseña).
- No cambies los parámetros de Argon2id, la derivación de subclaves BLAKE2b ni el algoritmo de permutación LSB (`crypto::permutation`) sin discutirlo antes en un *issue*: hacerlo rompe la lectura de los archivos ya creados.
- El test `crypto::tests::format_is_pinned` protege estos valores dorados.

### Comprobaciones locales antes de enviar un PR

La CI exige que todo pase sin avisos:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node --check gui/src/main.js
node --check gui/src/i18n.js
```
