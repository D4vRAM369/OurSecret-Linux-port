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

use std::fs::{File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::Path;

use zeroize::Zeroizing;

use crate::crypto::{self, GCM_TAG_LEN, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{OurSecretError, Result};

const TRAILER_LEN: usize = 8;
/// Mínimo payload = nonce + tag GCM (ciphertext de 0 bytes de claro).
const MIN_PAYLOAD: usize = NONCE_LEN + GCM_TAG_LEN;
/// Overhead fijo al final: sal + trailer.
const TAIL_LEN: usize = SALT_LEN + TRAILER_LEN;

/// Construye el bloque `[nonce | ciphertext | salt | trailer]` listo para
/// pegar al final de cualquier portador.
fn build_tail(plain_blob: &[u8], password: &str) -> Result<Vec<u8>> {
    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = Zeroizing::new(crypto::derive_key(password, &salt)?);
    let ciphertext = crypto::encrypt(&key, &nonce, plain_blob)?;

    // payload = nonce || ciphertext (lo que hay entre el portador y la sal).
    let payload_len = NONCE_LEN + ciphertext.len();
    let obf = (payload_len as u64) ^ mask_u64(&key);

    let mut tail = Vec::with_capacity(payload_len + TAIL_LEN);
    tail.extend_from_slice(&nonce);
    tail.extend_from_slice(&ciphertext);
    tail.extend_from_slice(&salt);
    tail.extend_from_slice(&obf.to_le_bytes());
    Ok(tail)
}

/// Esconde `plain_blob` al final de `carrier`. Devuelve el
/// archivo resultante listo para escribir.
pub fn embed(carrier: &[u8], plain_blob: &[u8], password: &str) -> Result<Vec<u8>> {
    let tail = build_tail(plain_blob, password)?;
    let mut out = Vec::with_capacity(carrier.len() + tail.len());
    out.extend_from_slice(carrier);
    out.extend_from_slice(&tail);
    Ok(out)
}

/// Variante por flujo de [`embed`]: copia el portador sin cargarlo entero en RAM.
pub fn embed_file(
    carrier_path: &Path,
    plain_blob: &[u8],
    password: &str,
    output_path: &Path,
) -> Result<()> {
    let tail = build_tail(plain_blob, password)?;
    let same_file =
        output_path.exists() && carrier_path.canonicalize().ok() == output_path.canonicalize().ok();

    if same_file {
        let mut out = OpenOptions::new().append(true).open(output_path)?;
        let orig_len = out.metadata()?.len();
        if let Err(e) = out.write_all(&tail) {
            // Si falla a mitad (p. ej. disco lleno), restauramos el tamaño original
            // para no dejar el portador truncado o corrupto.
            let _ = out.set_len(orig_len);
            return Err(e.into());
        }
    } else {
        let mut src = File::open(carrier_path)?;
        let mut out = File::create(output_path)?;
        std::io::copy(&mut src, &mut out)?;
        out.write_all(&tail)?;
    }
    Ok(())
}

/// Valida los últimos `TAIL_LEN` bytes, deriva la clave y devuelve
/// `(key, payload_len)` si la longitud encaja dentro de `total_len`.
fn parse_tail(
    tail: &[u8; TAIL_LEN],
    total_len: u64,
    password: &str,
) -> Result<(Zeroizing<[u8; KEY_LEN]>, usize)> {
    let mut salt = [0u8; SALT_LEN];
    salt.copy_from_slice(&tail[..SALT_LEN]);
    let key = Zeroizing::new(crypto::derive_key(password, &salt)?);

    let obf = u64::from_le_bytes(tail[SALT_LEN..].try_into().unwrap());
    let payload_len_u64 = obf ^ mask_u64(&key);
    let salt_start = total_len - TAIL_LEN as u64;

    if payload_len_u64 < MIN_PAYLOAD as u64 || payload_len_u64 > salt_start {
        return Err(OurSecretError::NotAContainer);
    }
    let payload_len =
        usize::try_from(payload_len_u64).map_err(|_| OurSecretError::NotAContainer)?;
    Ok((key, payload_len))
}

fn decrypt_payload(key: &[u8; KEY_LEN], payload: &[u8]) -> Result<Vec<u8>> {
    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload[..NONCE_LEN]);
    let ciphertext = &payload[NONCE_LEN..];
    crypto::decrypt(key, &nonce, ciphertext)
}

/// Extrae y descifra un archivo generado por `embed`. Devuelve el
/// `plain_blob`.
pub fn extract(stego: &[u8], password: &str) -> Result<Vec<u8>> {
    if stego.len() < MIN_PAYLOAD + TAIL_LEN {
        return Err(OurSecretError::NotAContainer);
    }
    let n = stego.len();
    let salt_start = n - TAIL_LEN;
    let tail: &[u8; TAIL_LEN] = stego[salt_start..].try_into().unwrap();
    let (key, payload_len) = parse_tail(tail, n as u64, password)?;
    let payload = &stego[salt_start - payload_len..salt_start];
    decrypt_payload(&key, payload)
}

/// Variante O(1) de [`extract`]: lee solo el final del archivo sin cargar
/// portadores grandes (p. ej. vídeos) en memoria.
pub fn extract_from_file(path: &Path, password: &str) -> Result<Vec<u8>> {
    let mut f = File::open(path)?;
    let file_len = f.metadata()?.len();
    if file_len < (MIN_PAYLOAD + TAIL_LEN) as u64 {
        return Err(OurSecretError::NotAContainer);
    }
    f.seek(SeekFrom::End(-(TAIL_LEN as i64)))?;
    let mut tail = [0u8; TAIL_LEN];
    f.read_exact(&mut tail)?;

    let (key, payload_len) = parse_tail(&tail, file_len, password)?;
    let payload_start = file_len - TAIL_LEN as u64 - payload_len as u64;
    f.seek(SeekFrom::Start(payload_start))?;
    let mut payload = vec![0u8; payload_len];
    f.read_exact(&mut payload)?;
    decrypt_payload(&key, &payload)
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
