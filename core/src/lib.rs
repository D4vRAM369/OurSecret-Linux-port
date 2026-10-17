//! `oursecret-core`: núcleo de esteganografía + cifrado del port Linux de
//! OurSecret.
//!
//! Esto es una **reimplementación clean-room**: reconstruye la
//! funcionalidad observada en el OurSecret original (Windows, SecureKit.net)
//! a partir de análisis externo (comportamiento de la interfaz, tipos de
//! archivo involucrados), no de su código fuente ni de ingeniería inversa
//! a nivel de instrucción del binario protegido. El formato de contenedor,
//! los algoritmos criptográficos elegidos y el algoritmo de inserción de
//! bits son diseño propio — ver `docs/02_ARQUITECTURA.md` del proyecto
//! para el razonamiento completo.
//!
//! ## Flujo de alto nivel
//!
//! 1. [`bundle::pack`] empaqueta los items (archivos/mensajes) a esconder
//!    en un único blob (zip en memoria).
//! 2. [`format::build_container`] cifra ese blob con AES-256-GCM (clave
//!    derivada de la contraseña vía Argon2id) y le añade una cabecera.
//! 3. [`embed`] incrusta ese contenedor cifrado dentro del archivo
//!    portador, con una de dos estrategias ([`embed::EmbedMode`]).
//!
//! La extracción recorre los mismos pasos al revés.

pub mod bundle;
pub mod crypto;
pub mod embed;
pub mod error;
pub mod format;

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
    let plain_blob = bundle::pack(items)?;
    let container = format::build_container(&plain_blob, password)?;

    match mode {
        EmbedMode::Append => {
            let carrier_bytes = std::fs::read(carrier_path)?;
            let stego = embed::append::embed(&carrier_bytes, &container);
            std::fs::write(output_path, stego)?;
        }
        EmbedMode::Lsb => {
            let img = image::open(carrier_path)?;
            let capacity = embed::lsb::capacity_bytes(&img);
            if container.len() > capacity {
                return Err(OurSecretError::InsufficientCapacity {
                    needed: container.len(),
                    available: capacity,
                });
            }
            let stego_img = embed::lsb::embed(&img, &container)?;
            stego_img.save_with_format(output_path, image::ImageFormat::Png)?;
        }
    }
    Ok(())
}

/// Extrae y descifra los items escondidos en `stego_path` con `password`.
/// Detecta automáticamente si el archivo usa el modo `Append` (intenta
/// primero, es instantáneo) o `Lsb` (si el primero falla y el archivo es
/// una imagen soportada).
pub fn read(stego_path: &Path, password: &str) -> Result<Vec<Item>> {
    let raw = std::fs::read(stego_path)?;

    // Primero probamos el modo append: es barato (no decodifica imagen) y
    // si el archivo no es nuestro, falla rápido y limpio.
    if let Ok((_carrier, container)) = embed::append::extract(&raw) {
        let plain_blob = format::open_container(container, password)?;
        return bundle::unpack(&plain_blob);
    }

    // Si no, intentamos como imagen LSB.
    match image::load_from_memory(&raw) {
        Ok(img) => {
            let container = embed::lsb::extract(&img)?;
            let plain_blob = format::open_container(&container, password)?;
            bundle::unpack(&plain_blob)
        }
        Err(_) => Err(OurSecretError::NotAContainer),
    }
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

        // Contraseña incorrecta debe fallar, no devolver basura silenciosamente.
        let err = read(&output_path, "password-incorrecta").unwrap_err();
        assert!(matches!(err, OurSecretError::DecryptionFailed));
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
