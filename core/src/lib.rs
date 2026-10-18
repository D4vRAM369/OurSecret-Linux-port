//! `oursecret-core`: núcleo de esteganografía + cifrado del port Linux de
//! OurSecret.
//!
//! Esto es una **reimplementación clean-room**: reconstruye la
//! funcionalidad observada en el OurSecret original (Windows, SecureKit.net)
//! a partir de análisis externo (comportamiento de la interfaz, tipos de
//! archivo involucrados), no de su código fuente ni de ingeniería inversa
//! a nivel de instrucción del binario protegido. El formato de contenedor,
//! los algoritmos criptográficos elegidos y el algoritmo de inserción de
//! bits son diseño propio.
//!
//! ## Flujo de alto nivel
//!
//! 1. [`bundle::pack`] empaqueta los items (archivos/mensajes) a esconder
//!    en un único blob (zip en memoria).
//! 2. [`embed`] cifra ese blob con AES-256-GCM (clave derivada de la
//!    contraseña vía Argon2id, ver [`crypto`]) y lo incrusta dentro del
//!    archivo portador con una de dos estrategias ([`embed::EmbedMode`]).
//!    Sin cabecera ni firma: sin la contraseña no hay nada reconocible.
//!
//! La extracción recorre los mismos pasos al revés.

pub mod bundle;
pub mod crypto;
pub mod embed;
pub mod error;

use std::path::Path;

pub use bundle::Item;
pub use embed::EmbedMode;
pub use error::{OurSecretError, Result};

/// Esconde `items` dentro de `carrier_path`, protegidos con `password`,
/// usando la estrategia `mode`, y escribe el resultado en `output_path`.
///
/// - `EmbedMode::Append` acepta cualquier archivo portador.
/// - `EmbedMode::Lsb` solo acepta imágenes PNG o BMP, y el resultado
///   siempre se guarda como PNG (ver `embed::lsb` para el porqué).
pub fn hide(
    carrier_path: &Path,
    items: &[Item],
    password: &str,
    mode: EmbedMode,
    output_path: &Path,
) -> Result<()> {
    // Aquí y no en la CLI/GUI: así ninguna puerta de entrada se la salta.
    if password.is_empty() {
        return Err(OurSecretError::InvalidInput(
            "la contraseña no puede estar vacía",
        ));
    }
    let plain_blob = bundle::pack(items)?;

    match mode {
        EmbedMode::Append => {
            let carrier_bytes = std::fs::read(carrier_path)?;
            let stego = embed::append::embed(&carrier_bytes, &plain_blob, password)?;
            std::fs::write(output_path, stego)?;
        }
        EmbedMode::Lsb => {
            // Un error de E/S (no existe, sin permisos) se queda como Io; todo
            // lo demás significa "esto no es un PNG/BMP que sepamos leer".
            let img = image::open(carrier_path).map_err(|e| match e {
                image::ImageError::IoError(io) => OurSecretError::Io(io),
                other => OurSecretError::UnsupportedCarrierForLsb(other.to_string()),
            })?;
            // La comprobación de capacidad vive dentro de lsb::embed (devuelve
            // InsufficientCapacity con las cifras exactas).
            let stego_img = embed::lsb::embed(&img, &plain_blob, password)?;
            stego_img.save_with_format(output_path, image::ImageFormat::Png)?;
        }
    }
    Ok(())
}

/// Bytes de **contenido del usuario** que caben en modo LSB en esta imagen,
/// suponiendo un solo archivo con nombre de hasta 32 caracteres y datos que
/// no comprimen (el peor caso: fotos, zips, vídeos). Redondea a la baja: si
/// el contenido comprime, cabrá algo más; con varios items, cada uno resta
/// ~170 bytes más.
///
/// No es `embed::lsb::capacity_bytes`: esa cuenta el hueco para el payload
/// ya cifrado. Entre el archivo del usuario y ese hueco hay dos capas que
/// también ocupan sitio (medido con `bundle::pack` y datos aleatorios):
/// - cifrado: nonce (12) + tag GCM (16) = 28 bytes;
/// - zip: ~101 bytes fijos + 2 × longitud del nombre (cabecera local y
///   directorio central) + ~5 bytes por cada bloque DEFLATE (~32 KiB).
pub fn lsb_capacity(carrier_path: &Path) -> Result<usize> {
    const FIXED: usize = 28 + 101 + 2 * 32 + 7; // 7 de margen → 200
    let payload = embed::lsb::capacity_bytes(&image::open(carrier_path)?);
    let avail = payload.saturating_sub(FIXED);
    // ponytail: 1 byte por cada 4 KiB cubre los ~5 por 32 KiB de DEFLATE con margen.
    Ok(avail - avail / 4096)
}

/// Si `carrier_path` es una imagen PNG/BMP que el modo LSB puede usar.
pub fn is_lsb_carrier(carrier_path: &Path) -> bool {
    image::open(carrier_path).is_ok()
}

/// Extrae y descifra los items escondidos en `stego_path` con `password`.
/// Detecta automáticamente si el archivo usa el modo `Append` (intenta
/// primero, es instantáneo) o `Lsb` (si el primero falla y el archivo es
/// una imagen soportada).
pub fn read(stego_path: &Path, password: &str) -> Result<Vec<Item>> {
    let raw = std::fs::read(stego_path)?;

    // Probamos primero el modo append. Ojo: sin cabecera mágica no se
    // puede distinguir "no es nuestro" de "clave incorrecta" solo por la
    // estructura, así que intentamos SIEMPRE también el LSB antes de
    // rendirnos, y al final devolvemos el error más informativo.
    let append_res = embed::append::extract(&raw, password);
    if let Ok(plain_blob) = &append_res {
        return bundle::unpack(plain_blob);
    }

    let lsb_res = match image::load_from_memory(&raw) {
        Ok(img) => embed::lsb::extract(&img, password),
        Err(_) => Err(OurSecretError::NotAContainer),
    };
    if let Ok(plain_blob) = &lsb_res {
        return bundle::unpack(plain_blob);
    }

    // Ninguno descifró. Si alguno dijo "contraseña incorrecta" (la
    // estructura encajaba pero GCM falló), ese mensaje es más útil que un
    // genérico "no es un contenedor".
    Err(match (append_res, lsb_res) {
        (Err(OurSecretError::DecryptionFailed), _) | (_, Err(OurSecretError::DecryptionFailed)) => {
            OurSecretError::DecryptionFailed
        }
        (Err(e), _) => e,
        // Inalcanzable: si append_res fuese Ok ya habríamos vuelto arriba.
        (Ok(_), _) => OurSecretError::NotAContainer,
    })
}

/// Guarda un archivo extraído en `out_dir` **sin sobrescribir nunca nada**.
/// Si `name` ya existe, prueba `name (1).ext`, `name (2).ext`... Devuelve
/// la ruta final.
///
/// Por qué: `name` lo eligió quien creó el archivo escondido. `bundle`
/// ya impide que salga de `out_dir` (zip-slip), pero `.bashrc` es un
/// nombre válido: extrayendo en la carpeta personal, un `fs::write` normal
/// reemplazaría el tuyo. `create_new` hace la comprobación y la creación
/// en una sola operación del sistema operativo (sin hueco entre "¿existe?"
/// y "créalo" que otro proceso pueda aprovechar).
pub fn save_extracted_file(out_dir: &Path, name: &str, data: &[u8]) -> Result<std::path::PathBuf> {
    use std::io::Write;
    let base = Path::new(name);
    let stem = base
        .file_stem()
        .unwrap_or(base.as_os_str())
        .to_string_lossy();
    let ext = base
        .extension()
        .map(|e| format!(".{}", e.to_string_lossy()));
    // ponytail: tope de 1000 intentos; si hay más copias, error en vez de bucle infinito.
    for i in 0..1000 {
        let candidate = match i {
            0 => out_dir.join(name),
            _ => out_dir.join(format!("{stem} ({i}){}", ext.as_deref().unwrap_or(""))),
        };
        match std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&candidate)
        {
            Ok(mut f) => {
                f.write_all(data)?;
                return Ok(candidate);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(e.into()),
        }
    }
    Err(std::io::Error::new(
        std::io::ErrorKind::AlreadyExists,
        format!("demasiadas copias de {name} en {}", out_dir.display()),
    )
    .into())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[test]
    fn hide_and_read_roundtrip_append_mode() {
        let dir = tempfile::tempdir().unwrap();
        let carrier_path = dir.path().join("carrier.bin");
        let output_path = dir.path().join("stego.bin");

        std::fs::File::create(&carrier_path)
            .unwrap()
            .write_all(b"contenido de un archivo portador cualquiera")
            .unwrap();

        let items = vec![Item::Message {
            subject: "Prueba".into(),
            text: "mensaje secreto de integracion".into(),
        }];

        hide(
            &carrier_path,
            &items,
            "password123",
            EmbedMode::Append,
            &output_path,
        )
        .unwrap();
        let recovered = read(&output_path, "password123").unwrap();
        assert_eq!(recovered, items);

        // Contraseña incorrecta debe fallar, no devolver basura.
        // Sin cabecera mágica, "clave incorrecta" es,
        // a propósito, indistinguible de "este archivo no es nuestro":
        // ambos son un error de extracción, no un resultado válido.
        let err = read(&output_path, "password-incorrecta").unwrap_err();
        assert!(matches!(
            err,
            OurSecretError::DecryptionFailed | OurSecretError::NotAContainer
        ));
    }

    #[test]
    fn valid_encryption_of_garbage_errors_instead_of_panicking() {
        // Quien conoce la contraseña puede cifrar CUALQUIER cosa, no solo un
        // zip bien formado: `bundle::unpack` también es superficie hostil.
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("stego.bin");
        for blob in [
            &b""[..],
            b"no soy un zip",
            b"PK\x03\x04truncado",
            &[0xFFu8; 300],
        ] {
            let stego = embed::append::embed(b"portador", blob, "pw").unwrap();
            std::fs::write(&path, stego).unwrap();
            assert!(read(&path, "pw").is_err(), "blob={blob:?}");
        }
    }

    #[test]
    fn hide_rejects_empty_password() {
        let dir = tempfile::tempdir().unwrap();
        let carrier = dir.path().join("c.bin");
        let out = dir.path().join("o.bin");
        std::fs::write(&carrier, b"portador").unwrap();
        let items = [Item::File {
            name: "a".into(),
            data: vec![1],
        }];
        let err = hide(&carrier, &items, "", EmbedMode::Append, &out).unwrap_err();
        assert!(matches!(err, OurSecretError::InvalidInput(_)));
        assert!(!out.exists(), "no debe escribir nada");
    }

    #[test]
    fn lsb_on_non_image_carrier_says_why() {
        let dir = tempfile::tempdir().unwrap();
        let carrier = dir.path().join("notas.txt");
        let out = dir.path().join("o.png");
        std::fs::write(&carrier, b"esto no es una imagen").unwrap();
        let items = [Item::File {
            name: "a".into(),
            data: vec![1],
        }];
        let err = hide(&carrier, &items, "pw", EmbedMode::Lsb, &out).unwrap_err();
        assert!(
            matches!(err, OurSecretError::UnsupportedCarrierForLsb(_)),
            "{err:?}"
        );
        // Si el archivo no existe, sigue siendo un error de E/S, no "no es imagen".
        let missing = dir.path().join("no-existe.png");
        let err = hide(&missing, &items, "pw", EmbedMode::Lsb, &out).unwrap_err();
        assert!(matches!(err, OurSecretError::Io(_)), "{err:?}");
    }

    #[test]
    fn lsb_capacity_is_what_really_fits() {
        use rand::RngCore;
        let dir = tempfile::tempdir().unwrap();
        let carrier = dir.path().join("c.png");
        let out = dir.path().join("o.png");
        // 32×32: el caso del informe (anunciaba 364, cabían ~225).
        // 600×600: lo bastante grande para que cuente el sobrecoste de DEFLATE.
        for side in [32u32, 600] {
            image::DynamicImage::ImageRgb8(image::ImageBuffer::from_fn(side, side, |x, y| {
                image::Rgb([(x * 7 + y) as u8, x as u8, y as u8])
            }))
            .save(&carrier)
            .unwrap();
            let cap = lsb_capacity(&carrier).unwrap();
            let file = |len: usize| {
                let mut data = vec![0u8; len];
                rand::thread_rng().fill_bytes(&mut data); // no comprime: peor caso
                [Item::File {
                    name: "n".repeat(32),
                    data,
                }]
            };
            // Lo anunciado cabe de verdad...
            hide(&carrier, &file(cap), "pw", EmbedMode::Lsb, &out)
                .unwrap_or_else(|e| panic!("{side}px: anuncia {cap} y no cabe: {e}"));
            // ...y no se queda muy corto: un 1 % + 64 bytes más ya no cabe.
            let over = cap + cap / 100 + 64;
            assert!(
                hide(&carrier, &file(over), "pw", EmbedMode::Lsb, &out).is_err(),
                "{side}px: {over} bytes también caben, la cifra es demasiado pesimista"
            );
        }
    }

    #[test]
    fn save_extracted_file_never_overwrites() {
        let dir = tempfile::tempdir().unwrap();
        let victim = dir.path().join(".bashrc");
        std::fs::write(&victim, b"original").unwrap();

        let p1 = save_extracted_file(dir.path(), ".bashrc", b"malicioso").unwrap();
        let p2 = save_extracted_file(dir.path(), "nota.txt", b"a").unwrap();
        let p3 = save_extracted_file(dir.path(), "nota.txt", b"b").unwrap();

        assert_eq!(std::fs::read(&victim).unwrap(), b"original");
        assert_eq!(p1, dir.path().join(".bashrc (1)"));
        assert_eq!(p2, dir.path().join("nota.txt"));
        assert_eq!(p3, dir.path().join("nota (1).txt"));
        assert_eq!(std::fs::read(&p3).unwrap(), b"b");
    }

    #[test]
    fn hide_and_read_roundtrip_lsb_mode() {
        let dir = tempfile::tempdir().unwrap();
        let carrier_path = dir.path().join("carrier.png");
        let output_path = dir.path().join("stego.png");

        let buf = image::ImageBuffer::from_fn(128, 128, |x, y| {
            image::Rgba([
                ((x + y) % 256) as u8,
                (x % 256) as u8,
                (y % 256) as u8,
                255u8,
            ])
        });
        image::DynamicImage::ImageRgba8(buf)
            .save_with_format(&carrier_path, image::ImageFormat::Png)
            .unwrap();

        let items = vec![Item::File {
            name: "secreto.txt".into(),
            data: b"datos binarios del archivo secreto".to_vec(),
        }];

        hide(
            &carrier_path,
            &items,
            "otra-password",
            EmbedMode::Lsb,
            &output_path,
        )
        .unwrap();
        let recovered = read(&output_path, "otra-password").unwrap();
        assert_eq!(recovered, items);
    }
}
