//! Modo "append": funciona con cualquier archivo portador, a costa de que
//! el archivo resultante crece (igual que el modal "Hide more data: the
//! carrier file grows" del original).
//!
//! Formato del resultado:
//!
//! ```text
//! [ bytes originales del portador ] [ contenedor cifrado (format.rs) ] [ trailer: u64 LE = longitud del contenedor ]
//! ```
//!
//! Por qué un trailer con la longitud en vez de buscar la cabecera mágica
//! desde el principio: así la extracción es O(1) — se leen los últimos 8
//! bytes, se sabe exactamente cuántos bytes hay que leer hacia atrás, sin
//! tener que escanear el archivo entero buscando un patrón (que además
//! podría, por pura casualidad, aparecer también dentro del portador
//! original).

use crate::error::{OurSecretError, Result};
use crate::format;

const TRAILER_LEN: usize = 8;

/// Devuelve el archivo portador con el contenedor cifrado añadido al final.
pub fn embed(carrier: &[u8], container: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(carrier.len() + container.len() + TRAILER_LEN);
    out.extend_from_slice(carrier);
    out.extend_from_slice(container);
    out.extend_from_slice(&(container.len() as u64).to_le_bytes());
    out
}

/// Separa un archivo generado por `embed` en `(portador_original, contenedor_cifrado)`.
pub fn extract(stego_file: &[u8]) -> Result<(&[u8], &[u8])> {
    if stego_file.len() < TRAILER_LEN {
        return Err(OurSecretError::NotAContainer);
    }
    let (rest, trailer) = stego_file.split_at(stego_file.len() - TRAILER_LEN);
    let container_len = u64::from_le_bytes(trailer.try_into().unwrap()) as usize;

    if container_len > rest.len() {
        return Err(OurSecretError::NotAContainer);
    }
    let split_at = rest.len() - container_len;
    let (carrier, container) = rest.split_at(split_at);

    // Verificación extra: lo que creemos que es el contenedor debe empezar
    // de verdad con la cabecera mágica — si no, el "trailer" que leímos no
    // era realmente nuestro (archivo no reconocido, no un bug silencioso).
    if container.len() < 4 || container[0..4] != format::MAGIC {
        return Err(OurSecretError::NotAContainer);
    }

    Ok((carrier, container))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_then_extract_roundtrip() {
        let carrier = b"contenido original del archivo portador, cualquier tipo";
        let container = b"OSLXfake-container-bytes-for-the-test-1234567890";

        let stego = embed(carrier, container);
        assert!(stego.len() > carrier.len(), "el archivo debe crecer");

        let (recovered_carrier, recovered_container) = extract(&stego).unwrap();
        assert_eq!(recovered_carrier, carrier);
        assert_eq!(recovered_container, container);
    }

    #[test]
    fn extract_on_unrelated_file_fails_cleanly() {
        let err = extract(b"un archivo cualquiera sin nada oculto").unwrap_err();
        assert!(matches!(err, OurSecretError::NotAContainer));
    }
}
