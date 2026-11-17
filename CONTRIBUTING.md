# Contribuir a OurSecret Linux

¡Gracias por tu interés en mejorar este proyecto! Antes de abrir un *Pull Request*, ten en cuenta estas reglas esenciales.

## Regla *clean-room* (obligatoria)

Este proyecto es una reimplementación **clean-room** de OurSecret (Windows, SecureKit.net).

- **No** aceptamos código desensamblado, descompilado ni copiado del binario original (`OurSecret.exe`).
- **No** aceptamos cambios cuyo objetivo sea hacer el formato compatible con el del OurSecret original.
- Todo el código nuevo, comentarios y documentación deben estar en **español**.

## Estabilidad del formato

- El formato actual no incluye cabecera mágica ni número de versión a propósito (para no delatar su presencia sin la contraseña).
- No cambies los parámetros de Argon2id ni el algoritmo de permutación LSB (`crypto::permutation`) sin discutirlo antes en un *issue*: hacerlo rompe la lectura de todos los archivos ya creados.
- El test `crypto::tests::format_is_pinned` protege estos valores dorados.

## Comprobaciones locales antes de enviar un PR

La CI exige que todo pase sin avisos:

```bash
cargo fmt --all --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
node --check gui/src/main.js
```
