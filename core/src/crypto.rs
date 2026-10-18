//! Cifrado del contenido oculto.
//!
//! Decisión de arquitectura: el OurSecret original de Windows ofrecía 5 algoritmos
//! (AES, Blowfish, RC4, TEA, un XOR propio) más MD5/SHA para derivar la
//! clave desde la contraseña. De esos, hoy (2026) solo AES sigue siendo
//! buena práctica — RC4 está roto, Blowfish y TEA tienen debilidades
//! conocidas, y usar MD5/SHA directo sobre la contraseña es vulnerable a
//! fuerza bruta con GPU. Este port ofrece un único esquema, moderno y
//! bien parametrizado, en vez de replicar el menú de opciones original.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use rand::RngCore;
use rand::SeedableRng;

use crate::error::{OurSecretError, Result};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
/// Tag de autenticación que AES-GCM añade al final del ciphertext.
pub const GCM_TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32; // AES-256

/// Parámetros de Argon2id: el segundo perfil de la RFC 9106 §4
/// ("si no puedes permitirte 2 GiB"): m = 64 MiB, t = 3, p = 4.
///
/// Se escriben a mano en vez de usar `Argon2::default()` por dos motivos:
/// 1. El default de la librería (19 MiB, t=2) es solo el *mínimo* de OWASP.
/// 2. Un default puede cambiar al actualizar la librería, y como los
///    parámetros no se guardan en el archivo (no hay cabecera ni versión,
///    a propósito), eso rompería en silencio todos los archivos existentes.
///    Fijados aquí + el test `format_is_pinned`, eso no puede pasar sin que
///    un test falle.
const ARGON2_M_KIB: u32 = 64 * 1024;
const ARGON2_T: u32 = 3;
const ARGON2_P: u32 = 4;

/// Deriva una clave AES-256 a partir de una contraseña y una sal con
/// Argon2id (parámetros arriba).
///
/// Por qué Argon2id y no PBKDF2/SHA directo: Argon2id está diseñado para
/// ser caro en memoria además de en CPU, lo que hace mucho más costoso
/// montar un ataque de fuerza bruta en GPU/ASIC que con un hash simple.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<[u8; KEY_LEN]> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_LEN))
        .map_err(|e| OurSecretError::Kdf(e.to_string()))?;
    let mut key = [0u8; KEY_LEN];
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
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
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(*key);
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

/// Las primeras `k` posiciones de una permutación pseudoaleatoria de
/// `0..count`, determinista por `key` (todas distintas). En el modo LSB
/// decide EN QUÉ posiciones de la imagen van los bits del secreto: sin
/// esto, la inserción es secuencial y el ataque chi-cuadrado por prefijos
/// la detecta y ubica; con posiciones dispersas por toda la imagen, ese
/// ataque deja de funcionar.
///
/// Es un Fisher-Yates *parcial y disperso*: en vez de crear el array
/// `0..count` entero y barajarlo (4 bytes por byte de píxel: ~144 MB en una
/// foto de 12 MP), solo apunta en un `HashMap` las casillas que se han
/// intercambiado. Memoria O(k), no O(count). Y como Fisher-Yates fija la
/// posición `i` en el paso `i`, las primeras `k` salen iguales pidas `k` o
/// pidas más: quien extrae puede pedir exactamente las que necesita.
///
/// Escrito a mano (no `SliceRandom::shuffle` ni `gen_range` de `rand`)
/// porque `rand` no garantiza que esas funciones den el mismo resultado
/// entre versiones; aquí solo dependemos del flujo ChaCha20, que es un
/// algoritmo estándar. Lo vigila el test `format_is_pinned`.
pub fn permutation(key: &[u8; KEY_LEN], count: usize, k: usize) -> Vec<usize> {
    assert!(
        k <= count,
        "no se pueden sacar {k} posiciones distintas de {count}"
    );
    // Semilla distinta de la del keystream para no correlacionar máscara y
    // permutación (dominio separado: segundo bloque del keystream).
    let mut seed = [0u8; KEY_LEN];
    let mut rng0 = rand_chacha::ChaCha20Rng::from_seed(*key);
    rng0.fill_bytes(&mut seed); // descarta el primer bloque (reservado a la máscara)
    rng0.fill_bytes(&mut seed);
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(seed);
    let mut pick_j = |i: usize| i + uniform_below(&mut rng, (count - i) as u64) as usize;

    // Dos caminos, MISMO resultado (lo comprueba `dense_and_sparse_agree`):
    // - carga grande: array denso de u32 (4 B por posición, como antes);
    // - carga pequeña: HashMap con solo las casillas tocadas (~40 B cada una,
    //   como mucho 2k). Con k cerca de count el HashMap gastaría ~10× más.
    if k.saturating_mul(16) > count && u32::try_from(count).is_ok() {
        let mut idx: Vec<u32> = (0..count as u32).collect();
        for i in 0..k {
            idx.swap(i, pick_j(i));
        }
        idx.truncate(k);
        idx.into_iter().map(|v| v as usize).collect()
    } else {
        let mut swapped: HashMap<usize, usize> = HashMap::with_capacity(2 * k);
        let mut out = Vec::with_capacity(k);
        for i in 0..k {
            let j = pick_j(i);
            let at_i = *swapped.get(&i).unwrap_or(&i);
            let at_j = *swapped.get(&j).unwrap_or(&j);
            swapped.insert(j, at_i);
            out.push(at_j);
        }
        out
    }
}

/// Número uniforme en `0..n` a partir de bytes crudos de ChaCha20. Rechazo
/// en vez de un simple `% n`: el módulo favorece a los números pequeños
/// cuando `n` no divide a 2^64 (sesgo de módulo).
fn uniform_below(rng: &mut rand_chacha::ChaCha20Rng, n: u64) -> u64 {
    let zone = u64::MAX - (u64::MAX % n); // múltiplo de n más grande que cabe
    loop {
        let mut b = [0u8; 8];
        rng.fill_bytes(&mut b);
        let v = u64::from_le_bytes(b);
        if v < zone {
            return v % n;
        }
    }
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

    #[test]
    fn permutation_is_distinct_and_in_range() {
        let key = [7u8; KEY_LEN];
        for (count, k) in [(1, 1), (10, 10), (1000, 37), (5000, 5000)] {
            let p = permutation(&key, count, k);
            assert_eq!(p.len(), k);
            assert!(p.iter().all(|&x| x < count));
            let unique: std::collections::HashSet<_> = p.iter().collect();
            assert_eq!(
                unique.len(),
                k,
                "posiciones repetidas con count={count} k={k}"
            );
        }
    }

    #[test]
    fn dense_and_sparse_agree() {
        // k=10 sobre 100_000 va por el camino HashMap; k=50_000 por el denso.
        // Las 10 primeras tienen que coincidir: si no, extraer (que pide
        // exactamente las que necesita) leería otras posiciones que embed.
        let key = [42u8; KEY_LEN];
        let sparse = permutation(&key, 100_000, 10);
        let dense = permutation(&key, 100_000, 50_000);
        assert_eq!(sparse[..], dense[..10]);
    }

    /// Valores dorados. Si este test falla, el formato ha cambiado y TODOS
    /// los archivos ya generados dejarán de abrirse. Solo se actualiza a
    /// propósito (y documentándolo), nunca "para que pase".
    #[test]
    fn format_is_pinned() {
        let key = derive_key("pin", &[1u8; SALT_LEN]).unwrap();
        assert_eq!(hex(&key[..8]), "3d1a2ff5cf950256");
        assert_eq!(
            permutation(&[9u8; KEY_LEN], 1_000_000, 5),
            [699281, 264395, 803392, 36706, 402497]
        );
        assert_eq!(hex(&keystream(&[9u8; KEY_LEN], 8)), "f2a76980dfc7a492");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
