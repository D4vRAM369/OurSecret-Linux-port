//! Formato del "contenedor" cifrado — el blob que luego se esconde dentro
//! del archivo portador con una de las estrategias de `embed`.
//!
//! Este es un formato propio, documentado aquí mismo, deliberadamente
//! simple: no intenta ser compatible con el formato interno (desconocido,
//! protegido por un empaquetador comercial) del OurSecret original — ver
//! docs/06_SIGUIENTE_NIVEL.md del proyecto para el porqué de esa decisión.
//!
//! Layout en bytes (todo little-endian):
//!
//! ```text
//! offset  tamaño  campo
//! 0       4       magic = b"OSLX"
//! 4       1       version = 1
//! 5       16      salt (para Argon2id)
//! 21      12      nonce (para AES-256-GCM)
//! 33      8       longitud del ciphertext (u64 LE)
//! 41      N       ciphertext (incluye el tag de autenticación de GCM, 16 bytes al final)
//! ```

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{OurSecretError, Result};

pub const MAGIC: [u8; 4] = *b"OSLX";
pub const VERSION: u8 = 1;
const HEADER_LEN: usize = 4 + 1 + SALT_LEN + NONCE_LEN + 8;

/// Construye el contenedor cifrado a partir del blob (zip) ya empaquetado
/// y la contraseña del usuario. Genera sal y nonce aleatorios nuevos cada
/// vez — nunca hay que reutilizar un nonce con la misma clave en AES-GCM.
pub fn build_container(plain_blob: &[u8], password: &str) -> Result<Vec<u8>> {
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(password, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, plain_blob)?;

    let mut out = Vec::with_capacity(HEADER_LEN + ciphertext.len());
    out.extend_from_slice(&MAGIC);
    out.push(VERSION);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&(ciphertext.len() as u64).to_le_bytes());
    out.extend_from_slice(&ciphertext);
    Ok(out)
}

/// Abre un contenedor y devuelve el blob (zip) descifrado en claro.
pub fn open_container(container: &[u8], password: &str) -> Result<Vec<u8>> {
    if container.len() < HEADER_LEN {
        return Err(OurSecretError::NotAContainer);
    }
    if container[0..4] != MAGIC {
        return Err(OurSecretError::NotAContainer);
    }
    let version = container[4];
    if version != VERSION {
        return Err(OurSecretError::UnsupportedVersion(version));
    }

    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&container[5..5 + SALT_LEN]);

    let nonce_start = 5 + SALT_LEN;
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&container[nonce_start..nonce_start + NONCE_LEN]);

    let len_start = nonce_start + NONCE_LEN;
    let ct_len =
        u64::from_le_bytes(container[len_start..len_start + 8].try_into().unwrap()) as usize;

    let ct_start = len_start + 8;
    if container.len() < ct_start + ct_len {
        return Err(OurSecretError::NotAContainer);
    }
    let ciphertext = &container[ct_start..ct_start + ct_len];

    let key: [u8; KEY_LEN] = crypto::derive_key(password, &salt)?;
    crypto::decrypt(&key, &nonce, ciphertext)
}

/// Busca la cabecera mágica en un slice arbitrario de bytes (usado por el
/// modo "append": localiza dónde empieza el contenedor dentro del archivo
/// portador, buscando desde el final — ver `embed::append`).
pub fn find_magic(haystack: &[u8]) -> Option<usize> {
    if haystack.len() < MAGIC.len() {
        return None;
    }
    haystack
        .windows(MAGIC.len())
        .rposition(|window| window == MAGIC)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn build_then_open_roundtrip() {
        let plain = b"este es el contenido en claro del zip interno";
        let container = build_container(plain, "clave-123").unwrap();

        assert_eq!(&container[0..4], &MAGIC);
        assert_eq!(container[4], VERSION);

        let recovered = open_container(&container, "clave-123").unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn wrong_password_errors_cleanly() {
        let container = build_container(b"secreto", "buena").unwrap();
        let err = open_container(&container, "mala").unwrap_err();
        assert!(matches!(err, OurSecretError::DecryptionFailed));
    }

    #[test]
    fn garbage_input_is_not_a_container() {
        let err = open_container(b"esto no es un contenedor valido", "x").unwrap_err();
        assert!(matches!(err, OurSecretError::NotAContainer));
    }
}
