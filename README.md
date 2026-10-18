# OurSecret Linux

Esconde archivos y mensajes cifrados dentro de otros archivos (fotos, canciones, documentos). Para Linux y Windows, con CLI y GUI.

Es una reimplementación *clean-room* de OurSecret (SecureKit.net, solo Windows): reproduce lo que hace el original a partir de observar su comportamiento, sin copiar su código. **No es compatible** con los archivos del OurSecret original.

> ⚠️ **Estado: experimental.** No ha pasado una auditoría externa y el formato todavía puede cambiar sin compatibilidad hacia atrás (no lleva número de versión, a propósito). No lo uses para algo de lo que dependa tu seguridad.

## Cómo funciona

1. Los archivos y mensajes se empaquetan en un ZIP en memoria.
2. Se cifran con **AES-256-GCM**. La clave se deriva de tu contraseña con **Argon2id** (64 MiB, t=3, p=4).
3. El resultado se esconde en el archivo portador con uno de dos modos:

| Modo | Portador | Qué pasa con el archivo | ¿Se nota? |
|---|---|---|---|
| `append` (crece) | cualquiera | crece; los datos van al final | En PNG, JPEG, PDF y ZIP se ve que sobran bytes tras el final. En audio y vídeo, menos. |
| `lsb` (mismas dimensiones) | PNG o BMP | misma imagen; la salida es siempre PNG | Datos repartidos por toda la imagen según la clave, con ±1 matching. No lo detectan los análisis clásicos (chi², RS); el estegoanálisis moderno sí puede con cargas altas. |

Sin la contraseña, nada en el archivo indica que sea de este programa: no hay firma, cabecera ni longitud en claro.

## Uso

### CLI

```bash
# Esconder un archivo y un mensaje en una foto (la contraseña se pide si no se pasa con -p)
oursecret hide -c foto.png -o foto_secreta.png -f nota.txt -m "asunto:texto" --mode lsb

# Extraer (nunca sobrescribe: si nota.txt ya existe, guarda "nota (1).txt")
oursecret extract -i foto_secreta.png -o ./extraido

# ¿Cuánto cabe en esta imagen en modo lsb?
oursecret capacity -c foto.png
```

### GUI

Aplicación de escritorio Tauri: elige portador, añade archivos o mensajes, contraseña y modo.

## Compilar

Requisitos: Rust estable. Para la GUI en Linux, además, las librerías de WebKitGTK:

```bash
sudo apt-get install libwebkit2gtk-4.1-dev libgtk-3-dev libayatana-appindicator3-dev librsvg2-dev
```

```bash
cargo build --release -p oursecret-cli      # → target/release/oursecret
cargo test -p oursecret-core                # tests del núcleo

cd gui && npm install && npx tauri build    # → .deb y AppImage en target/release/bundle/
```

Windows: la CI (`.github/workflows/ci.yml`) compila `oursecret.exe` y `oursecret-gui.exe` en cada push y los deja como artefacto.

## Estructura

```
core/          oursecret-core: toda la lógica (cifrado, empaquetado, modos de ocultación)
cli/           oursecret: línea de comandos (hide / extract / capacity)
gui/           GUI Tauri: frontend HTML/JS en gui/src, backend Rust en gui/src-tauri
```

La CLI y la GUI son capas finas sobre `oursecret-core`.

## Seguridad: qué protege y qué no

- ✅ **Contenido:** sin la contraseña no se puede leer (AES-GCM también detecta manipulaciones).
- ✅ **Autoría:** nada en el archivo indica qué programa lo creó.
- ⚠️ **Existencia:** en modo `append` con PNG/JPEG/PDF/ZIP se nota que *hay algo*. En modo `lsb`, con cargas altas, el estegoanálisis moderno puede notarlo.
- ✅ **Archivos de terceros:** quien te manda un archivo conoce la contraseña y elige su contenido. Al extraer, la app no sobrescribe archivos existentes, no deja salir de la carpeta elegida (zip-slip), no interpreta los textos como HTML y limita el tamaño descomprimido (zip bombs).
- ⚠️ **Contraseña:** Argon2id frena la fuerza bruta, pero una contraseña corta o común se puede adivinar igual.

## Licencia

MIT.
