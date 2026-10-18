//! Modo "append": funciona con cualquier archivo portador, a costa de que
//! el archivo resultante crece (igual que el modal "Hide more data" del
//! original).
//!
//! # Formato (indetectable por firma)
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

use crate::crypto::{self, GCM_TAG_LEN, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{OurSecretError, Result};

const TRAILER_LEN: usize = 8;
/// Mínimo payload = nonce + tag GCM (ciphertext de 0 bytes de claro).
const MIN_PAYLOAD: usize = NONCE_LEN + GCM_TAG_LEN;
/// Overhead fijo al final: sal + trailer.
const TAIL_LEN: usize = SALT_LEN + TRAILER_LEN;

/// Esconde `plain_blob` al final de `carrier`. Devuelve el
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

/// Extrae y descifra un archivo generado por `embed`. Devuelve el
/// `plain_blob`.
pub fn extract(stego: &[u8], password: &str) -> Result<Vec<u8>> {
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
            "la salida no debe contener la antigua firma OSLX"
        );
    }

    #[test]
    fn hostile_input_errors_instead_of_panicking() {
        // Todos los tamaños alrededor del mínimo (antes y justo después de la KDF).
        for len in 0..=MIN_PAYLOAD + TAIL_LEN + 1 {
            let junk: Vec<u8> = (0..len).map(|i| (i * 37 % 251) as u8).collect();
            assert!(extract(&junk, "pw").is_err(), "len={len}");
        }

        // Trailer fabricado para que la longitud descifrada con "pw" sea
        // `claimed`: así se prueban los límites que bytes al azar no alcanzan.
        let total = 200;
        let salt = [3u8; SALT_LEN];
        let mask = mask_u64(&crypto::derive_key("pw", &salt).unwrap());
        let salt_start = (total - TAIL_LEN) as u64;
        for claimed in [
            0,
            MIN_PAYLOAD as u64 - 1,
            MIN_PAYLOAD as u64, // pasa el filtro → GCM rechaza la basura
            salt_start,         // payload = todo el archivo → idem
            salt_start + 1,     // empezaría antes del byte 0
            u64::MAX,           // restar desbordaría
        ] {
            let mut stego = vec![0xA5u8; total];
            stego[total - TAIL_LEN..total - TRAILER_LEN].copy_from_slice(&salt);
            stego[total - TRAILER_LEN..].copy_from_slice(&(claimed ^ mask).to_le_bytes());
            let err = extract(&stego, "pw").unwrap_err();
            assert!(
                matches!(
                    err,
                    OurSecretError::NotAContainer | OurSecretError::DecryptionFailed
                ),
                "claimed={claimed}: {err:?}"
            );
        }
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
