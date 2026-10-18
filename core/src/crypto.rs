//! Cifrado del contenido oculto.
//!
//! Decisión de arquitectura (documentada también en docs/02_ARQUITECTURA.md
//! del proyecto): el OurSecret original de Windows ofrecía 5 algoritmos
//! (AES, Blowfish, RC4, TEA, un XOR propio) más MD5/SHA para derivar la
//! clave desde la contraseña. De esos, hoy (2026) solo AES sigue siendo
//! buena práctica — RC4 está roto, Blowfish y TEA tienen debilidades
//! conocidas, y usar MD5/SHA directo sobre la contraseña es vulnerable a
//! fuerza bruta con GPU. Este port ofrece un único esquema, moderno y
//! bien parametrizado, en vez de replicar el menú de opciones original.

use aes_gcm::aead::{Aead, KeyInit, OsRng};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::Argon2;
use rand::RngCore;

use crate::error::{OurSecretError, Result};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
/// Tag de autenticación que AES-GCM añade al final del ciphertext.
pub const GCM_TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32; // AES-256

/// Deriva una clave AES-256 a partir de una contraseña y una sal, usando
/// Argon2id con los parámetros por defecto de la librería `argon2` 0.5
/// (m = 19 MiB, t = 2, p = 1). Ojo: eso es el *mínimo* que recomienda la
/// OWASP Password Storage Cheat Sheet, no un perfil de RFC 9106 (la RFC
/// propone t=1,p=4,m=2 GiB o t=3,p=4,m=64 MiB). Medido: ~18 ms por intento
/// en un Ryzen 5 5600G. Los parámetros no se guardan en el archivo (no hay
/// cabecera ni versión, a propósito): cambiarlos rompe la lectura de todos
/// los archivos ya generados.
///
/// Por qué Argon2id y no PBKDF2/SHA directo: Argon2id está diseñado para
/// ser caro en memoria además de en CPU, lo que hace mucho más costoso
/// montar un ataque de fuerza bruta en GPU/ASIC que con un hash simple.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let mut key = [0u8; KEY_LEN];
    Argon2::default()
        .hash_password_into(password.as_bytes(), salt, &mut key)
        .map_err(|e| OurSecretError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Flujo de bytes pseudoaleatorio determinista derivado de la clave, para
/// los dos modos de `embed`: se usa como máscara XOR de la longitud (que así no viaja
/// en claro) y como semilla de la permutación de posiciones en LSB.
///
/// Usa ChaCha20 sembrado con la clave de 32 bytes que ya salió de Argon2id.
/// Mismo (clave) => mismo flujo => quien tiene la contraseña reconstruye
/// máscara y permutación; quien no, ve bytes indistinguibles de ruido.
pub fn keystream(key: &[u8; KEY_LEN], len: usize) -> Vec<u8> {
    use rand::SeedableRng;
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(*key);
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

/// Permutación pseudoaleatoria de `0..count`, determinista por `key`. En
/// el modo LSB decide EN QUÉ posiciones de la imagen van los bits del secreto:
/// sin esto, la inserción es secuencial y el ataque chi-cuadrado por
/// prefijos la detecta y ubica; con posiciones dispersas por toda la
/// imagen, ese ataque deja de funcionar.
pub fn permutation(key: &[u8; KEY_LEN], count: usize) -> Vec<u32> {
    use rand::seq::SliceRandom;
    use rand::SeedableRng;
    // Semilla distinta de la del keystream para no correlacionar máscara y
    // permutación (dominio separado: segundo bloque del keystream).
    let mut seed = [0u8; KEY_LEN];
    let mut rng0 = rand_chacha::ChaCha20Rng::from_seed(*key);
    rng0.fill_bytes(&mut seed); // descarta el primer bloque (reservado a la máscara)
    rng0.fill_bytes(&mut seed);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let mut idx: Vec<u32> = (0..count as u32).collect();
    idx.shuffle(&mut rng);
    idx
}

pub fn random_salt() -> [u8; SALT_LEN] {
    let mut salt = [0u8; SALT_LEN];
    rand::thread_rng().fill_bytes(&mut salt);
    salt
}

pub fn random_nonce() -> [u8; NONCE_LEN] {
    let mut nonce = [0u8; NONCE_LEN];
    rand::thread_rng().fill_bytes(&mut nonce);
    nonce
}

/// Cifra `plaintext` con AES-256-GCM. GCM es cifrado *autenticado*: además
/// de ocultar el contenido, detecta si alguien lo modificó (a diferencia
/// del original, que usaba MD5 como simple checksum de integridad, no
/// como protección criptográfica real).
pub fn encrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], plaintext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(Nonce::from_slice(nonce), plaintext)
        .map_err(|_| OurSecretError::DecryptionFailed) // encrypt no debería fallar nunca en la práctica
}

pub fn decrypt(key: &[u8; KEY_LEN], nonce: &[u8; NONCE_LEN], ciphertext: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(Nonce::from_slice(nonce), ciphertext)
        .map_err(|_| OurSecretError::DecryptionFailed)
}

/// Solo para que `OsRng` quede referenciado y el linter no se queje si en
/// el futuro se usa directamente aquí en vez de a través de `rand`.
#[allow(dead_code)]
fn _silence_unused_import() {
    let _ = OsRng;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrip() {
        let salt = random_salt();
        let key = derive_key("correct horse battery staple", &salt).unwrap();
        let nonce = random_nonce();
        let msg = b"hola brian, esto es un mensaje secreto";

        let ct = encrypt(&key, &nonce, msg).unwrap();
        assert_ne!(ct, msg, "el texto cifrado no debe ser igual al original");

        let pt = decrypt(&key, &nonce, &ct).unwrap();
        assert_eq!(pt, msg);
    }

    #[test]
    fn wrong_password_fails_to_decrypt() {
        let salt = random_salt();
        let key_good = derive_key("contraseña-correcta", &salt).unwrap();
        let key_bad = derive_key("contraseña-incorrecta", &salt).unwrap();
        let nonce = random_nonce();

        let ct = encrypt(&key_good, &nonce, b"secreto").unwrap();
        let result = decrypt(&key_bad, &nonce, &ct);
        assert!(matches!(result, Err(OurSecretError::DecryptionFailed)));
    }
}
