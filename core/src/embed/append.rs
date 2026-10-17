//! Modo "append": funciona con cualquier archivo portador, a costa de que
//! el archivo resultante crece (igual que el modal "Hide more data" del
//! original).
//!
//! # Formato v2 (actual, indetectable por firma)
//!
//! ```text
//! [ bytes originales del portador ] [ nonce(12) ] [ ciphertext ] [ salt(16) ] [ trailer: u64 LE ]
//! ```
//!
//! - **Sin cabecera mágica ni byte de versión:** nada identifica el blob
//!   como nuestro. GCM autentica en la extracción (si la clave es mala, o
//!   los bytes no son nuestros, falla igual) — eso sustituye a la magia.
//! - **El `trailer` NO es la longitud en claro:** es
//!   `longitud_del_payload XOR máscara`, donde la máscara sale de la clave
//!   (Argon2 → ChaCha). Sin la contraseña, esos 8 bytes finales parecen
//!   aleatorios, como los de cualquier archivo.
//! - **La sal va en una posición fija desde el final** (bytes -24..-8), no
//!   al principio del blob: hace falta para derivar la clave *antes* de
//!   poder descifrar la longitud, así que no puede depender de ella. La sal
//!   es pública (16 bytes aleatorios), no revela nada por sí sola.
//!
//! La extracción: leer los últimos 8 bytes y los 16 anteriores (sal),
//! derivar la clave, descifrar la longitud, saltar hacia atrás esa cantidad.
//! O(1), sin escanear.
//!
//! # Formato v1 (solo lectura, archivos antiguos)
//!
//! `[ portador ] [ OSLX... contenedor con magia ] [ u64 LE longitud ]`.
//! Se intenta al leer si el v2 no encaja, para no romper archivos ya
//! generados. No se escribe nunca más.

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{OurSecretError, Result};
use crate::format::{self, GCM_TAG_LEN};

const TRAILER_LEN: usize = 8;
/// Mínimo payload v2 = nonce + tag GCM (ciphertext de 0 bytes de claro).
const MIN_PAYLOAD: usize = NONCE_LEN + GCM_TAG_LEN;
/// Overhead fijo al final: sal + trailer.
const TAIL_LEN: usize = SALT_LEN + TRAILER_LEN;

/// Esconde `plain_blob` al final de `carrier`, formato v2. Devuelve el
/// archivo resultante listo para escribir.
pub fn embed(carrier: &[u8], plain_blob: &[u8], password: &str) -> Result<Vec<u8>> {
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(password, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, plain_blob)?;

    // payload = nonce || ciphertext (lo que hay entre el portador y la sal).
    let payload_len = NONCE_LEN + ciphertext.len();
    let obf = (payload_len as u64) ^ mask_u64(&key);

    let mut out = Vec::with_capacity(carrier.len() + payload_len + TAIL_LEN);
    out.extend_from_slice(carrier);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ciphertext);
    out.extend_from_slice(&salt);
    out.extend_from_slice(&obf.to_le_bytes());
    Ok(out)
}

/// Extrae y descifra un archivo generado por `embed` (v2). Devuelve el
/// `plain_blob`. Si los bytes no encajan como contenedor v2, intenta el
/// formato v1 antiguo antes de rendirse.
pub fn extract(stego: &[u8], password: &str) -> Result<Vec<u8>> {
    match extract_v2(stego, password) {
        // Si v2 descifró o dio "contraseña incorrecta" sobre una estructura
        // que SÍ encajaba, ese es el veredicto. Solo si "no parece v2"
        // (NotAContainer) probamos el formato antiguo.
        Err(OurSecretError::NotAContainer) => extract_v1(stego, password),
        other => other,
    }
}

fn extract_v2(stego: &[u8], password: &str) -> Result<Vec<u8>> {
    if stego.len() < MIN_PAYLOAD + TAIL_LEN {
        return Err(OurSecretError::NotAContainer);
    }
    let n = stego.len();

    // Sal en posición fija desde el final: [n-24 .. n-8].
    let salt_start = n - TAIL_LEN;
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&stego[salt_start..salt_start + SALT_LEN]);

    let key = crypto::derive_key(password, &salt)?;

    let obf = u64::from_le_bytes(stego[n - TRAILER_LEN..].try_into().unwrap());
    let payload_len = (obf ^ mask_u64(&key)) as usize;

    // La longitud descifrada tiene que apuntar a un límite válido dentro
    // del archivo; si no, no era nuestro (o la clave es incorrecta): en
    // ambos casos "no es un contenedor" para que `read` pueda probar LSB.
    if payload_len < MIN_PAYLOAD || payload_len > salt_start {
        return Err(OurSecretError::NotAContainer);
    }
    let payload_start = salt_start - payload_len;
    let payload = &stego[payload_start..salt_start];

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload[..NONCE_LEN]);
    let ciphertext = &payload[NONCE_LEN..];

    crypto::decrypt(&key, &nonce, ciphertext)
}

/// Lectura del formato v1 (con cabecera mágica OSLX). Solo para archivos
/// generados antes del v2.
fn extract_v1(stego: &[u8], password: &str) -> Result<Vec<u8>> {
    if stego.len() < TRAILER_LEN {
        return Err(OurSecretError::NotAContainer);
    }
    let (rest, trailer) = stego.split_at(stego.len() - TRAILER_LEN);
    let container_len = u64::from_le_bytes(trailer.try_into().unwrap()) as usize;
    if container_len > rest.len() {
        return Err(OurSecretError::NotAContainer);
    }
    let container = &rest[rest.len() - container_len..];
    if container.len() < 4 || container[0..4] != format::MAGIC {
        return Err(OurSecretError::NotAContainer);
    }
    format::open_container(container, password)
}

/// Primeros 8 bytes del keystream derivado de la clave, como u64 LE. Máscara
/// XOR de la longitud: oculta cuántos bytes se añadieron.
fn mask_u64(key: &[u8; KEY_LEN]) -> u64 {
    let ks = crypto::keystream(key, 8);
    u64::from_le_bytes(ks.try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn embed_then_extract_roundtrip() {
        let carrier = b"contenido original del archivo portador, cualquier tipo";
        let plain = b"blob interno de prueba 1234567890";

        let stego = embed(carrier, plain, "clave").unwrap();
        assert!(stego.len() > carrier.len(), "el archivo debe crecer");
        // El portador original queda intacto al principio.
        assert_eq!(&stego[..carrier.len()], carrier);

        let recovered = extract(&stego, "clave").unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn wrong_password_does_not_leak_as_success() {
        let stego = embed(b"portador", b"secreto", "buena").unwrap();
        // Con clave mala: o bien la longitud descifrada no cuadra
        // (NotAContainer) o bien GCM falla (DecryptionFailed). Nunca OK.
        assert!(extract(&stego, "mala").is_err());
    }

    #[test]
    fn no_magic_bytes_in_output() {
        let stego = embed(b"portador cualquiera", b"secreto", "clave").unwrap();
        assert!(
            stego.windows(4).all(|w| w != b"OSLX"),
            "el v2 no debe contener la firma OSLX"
        );
    }

    #[test]
    fn extract_on_unrelated_file_fails_cleanly() {
        let err = extract(b"un archivo cualquiera sin nada oculto", "x").unwrap_err();
        assert!(matches!(
            err,
            OurSecretError::NotAContainer | OurSecretError::DecryptionFailed
        ));
    }
}
