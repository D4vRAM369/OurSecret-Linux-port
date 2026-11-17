//! Cifrado del contenido oculto (formato v3).
//!
//! Decisión de arquitectura: el OurSecret original de Windows ofrecía 5 algoritmos
//! (AES, Blowfish, RC4, TEA, un XOR propio) más MD5/SHA para derivar la
//! clave desde la contraseña. De esos, hoy (2026) solo AES sigue siendo
//! buena práctica — RC4 está roto, Blowfish y TEA tienen debilidades
//! conocidas, y usar MD5/SHA directo sobre la contraseña es vulnerable a
//! fuerza bruta con GPU. Este port ofrece un único esquema, moderno y
//! bien parametrizado, en vez de replicar el menú de opciones original.
//!
//! En **v3** se añaden tres mejoras respecto a v2:
//! 1. `derive_key` devuelve `Zeroizing<[u8; 32]>` directamente.
//! 2. Separación de dominios mediante `subkey` (BLAKE2b-MAC) para obtener
//!    claves independientes para cifrado (AES-GCM), máscara de longitud y
//!    permutación LSB.
//! 3. `encrypt` y `decrypt` autentican AAD (*Additional Authenticated Data*):
//!    la sal y la longitud enmascarada quedan vinculadas al tag GCM.

use std::collections::HashMap;

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Key, Nonce};
use argon2::{Algorithm, Argon2, Params, Version};
use blake2::digest::consts::U32;
use blake2::digest::Mac;
use blake2::{Blake2b, Blake2bMac, Digest};
use rand::RngCore;
use rand::SeedableRng;
use zeroize::Zeroizing;

use crate::error::{OurSecretError, Result};

pub const SALT_LEN: usize = 16;
pub const NONCE_LEN: usize = 12;
/// Tag de autenticación que AES-GCM añade al final del ciphertext.
pub const GCM_TAG_LEN: usize = 16;
pub const KEY_LEN: usize = 32; // AES-256

/// Etiquetas de separación de dominios para derivar subclaves desde la clave
/// maestra de Argon2id (formato v3).
pub const LABEL_ENC: &[u8] = b"oursecret-v3-enc";
pub const LABEL_MASK: &[u8] = b"oursecret-v3-mask";
pub const LABEL_PERM: &[u8] = b"oursecret-v3-perm";

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

/// Deriva una clave maestra de 256 bits a partir de una contraseña y una sal
/// con Argon2id (parámetros arriba).
///
/// Devuelve `Zeroizing<[u8; KEY_LEN]>` para limpiar la RAM automáticamente al
/// salir de ámbito sin exponer copias intermedias en la pila.
pub fn derive_key(password: &str, salt: &[u8; SALT_LEN]) -> Result<Zeroizing<[u8; KEY_LEN]>> {
    let params = Params::new(ARGON2_M_KIB, ARGON2_T, ARGON2_P, Some(KEY_LEN))
        .map_err(|e| OurSecretError::Kdf(e.to_string()))?;
    let mut key = Zeroizing::new([0u8; KEY_LEN]);
    Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into(password.as_bytes(), salt, &mut *key)
        .map_err(|e| OurSecretError::Kdf(e.to_string()))?;
    Ok(key)
}

/// Deriva una subclave de 256 bits con separación de dominios usando
/// BLAKE2b-MAC con la clave maestra como clave y `label` como contexto.
pub fn subkey(master: &[u8; KEY_LEN], label: &[u8]) -> Zeroizing<[u8; KEY_LEN]> {
    let mut mac = <Blake2bMac<U32> as Mac>::new_from_slice(master)
        .expect("KEY_LEN (32) es siempre válido para BLAKE2b-MAC");
    mac.update(label);
    let mut out = Zeroizing::new([0u8; KEY_LEN]);
    out.copy_from_slice(&mac.finalize().into_bytes());
    out
}

/// Hash público BLAKE2b-256 sobre varias piezas (p. ej. semilla pública para
/// dispersar la cabecera LSB en función de las dimensiones de la imagen).
pub fn hash_seed(parts: &[&[u8]]) -> [u8; KEY_LEN] {
    let mut hasher = Blake2b::<U32>::new();
    for p in parts {
        hasher.update(p);
    }
    let mut out = [0u8; KEY_LEN];
    out.copy_from_slice(&hasher.finalize());
    out
}

/// Flujo de bytes pseudoaleatorio determinista derivado de una semilla de 32 bytes
/// (p. ej. `subkey(master, LABEL_MASK)`), usado como máscara XOR de la longitud.
pub fn keystream(seed: &[u8; KEY_LEN], len: usize) -> Vec<u8> {
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
    let mut out = vec![0u8; len];
    rng.fill_bytes(&mut out);
    out
}

/// Las primeras `k` posiciones de una permutación pseudoaleatoria de
/// `0..count`, determinista por `seed` (todas distintas).
///
/// Es un Fisher-Yates *parcial y disperso*: en vez de crear el array
/// `0..count` entero y barajarlo (~144 MB en una foto de 12 MP), solo apunta
/// en un `HashMap` las casillas que se han intercambiado. Memoria O(k).
///
/// Escrito a mano (no `SliceRandom::shuffle` ni `gen_range` de `rand`)
/// porque `rand` no garantiza que esas funciones den el mismo resultado
/// entre versiones; aquí solo dependemos del flujo ChaCha20, que es un
/// algoritmo estándar. Lo vigila el test `format_is_pinned`.
pub fn permutation(seed: &[u8; KEY_LEN], count: usize, k: usize) -> Vec<usize> {
    assert!(
        k <= count,
        "no se pueden sacar {k} posiciones distintas de {count}"
    );
    let mut rng = rand_chacha::ChaCha20Rng::from_seed(*seed);
    let mut pick_j = |i: usize| i + uniform_below(&mut rng, (count - i) as u64) as usize;

    // Dos caminos, MISMO resultado (lo comprueba `dense_and_sparse_agree`).
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

/// Cifra `plaintext` con AES-256-GCM autenticando también `aad` (sal + longitud
/// enmascarada, aunque no vayan cifrados dentro del payload).
pub fn encrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    plaintext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .encrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: plaintext,
                aad,
            },
        )
        .map_err(|_| OurSecretError::DecryptionFailed)
}

pub fn decrypt(
    key: &[u8; KEY_LEN],
    nonce: &[u8; NONCE_LEN],
    ciphertext: &[u8],
    aad: &[u8],
) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(key));
    cipher
        .decrypt(
            Nonce::from_slice(nonce),
            Payload {
                msg: ciphertext,
                aad,
            },
        )
        .map_err(|_| OurSecretError::DecryptionFailed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn encrypt_then_decrypt_roundtrip_with_aad() {
        let salt = random_salt();
        let master = derive_key("correct horse battery staple", &salt).unwrap();
        let enc_key = subkey(&master, LABEL_ENC);
        let nonce = random_nonce();
        let msg = b"hola brian, esto es un mensaje secreto";
        let aad = b"metadatos-autenticados";

        let ct = encrypt(&enc_key, &nonce, msg, aad).unwrap();
        let pt = decrypt(&enc_key, &nonce, &ct, aad).unwrap();
        assert_eq!(pt, msg);

        // Alterar un solo byte de AAD debe invalidar el tag GCM.
        assert!(matches!(
            decrypt(&enc_key, &nonce, &ct, b"metadatos-alterado!"),
            Err(OurSecretError::DecryptionFailed)
        ));
    }

    #[test]
    fn subkeys_are_domain_separated() {
        let master = [0x42u8; KEY_LEN];
        let k_enc = subkey(&master, LABEL_ENC);
        let k_mask = subkey(&master, LABEL_MASK);
        let k_perm = subkey(&master, LABEL_PERM);
        assert_ne!(&*k_enc, &master);
        assert_ne!(&*k_enc, &*k_mask);
        assert_ne!(&*k_enc, &*k_perm);
        assert_ne!(&*k_mask, &*k_perm);
    }

    #[test]
    fn wrong_password_fails_to_decrypt() {
        let salt = random_salt();
        let key_good = subkey(
            &derive_key("contraseña-correcta", &salt).unwrap(),
            LABEL_ENC,
        );
        let key_bad = subkey(
            &derive_key("contraseña-incorrecta", &salt).unwrap(),
            LABEL_ENC,
        );
        let nonce = random_nonce();

        let ct = encrypt(&key_good, &nonce, b"secreto", b"aad").unwrap();
        let result = decrypt(&key_bad, &nonce, &ct, b"aad");
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
        let key = [42u8; KEY_LEN];
        let sparse = permutation(&key, 100_000, 10);
        let dense = permutation(&key, 100_000, 50_000);
        assert_eq!(sparse[..], dense[..10]);
    }

    /// Valores dorados (formato v3). Si este test falla, el formato ha cambiado
    /// y TODOS los archivos ya generados dejarán de abrirse. Solo se actualiza a
    /// propósito (y documentándolo), nunca "para que pase".
    #[test]
    fn format_is_pinned() {
        let master = derive_key("pin", &[1u8; SALT_LEN]).unwrap();
        assert_eq!(hex(&master[..8]), "3d1a2ff5cf950256");

        let k_enc = subkey(&master, LABEL_ENC);
        let k_mask = subkey(&master, LABEL_MASK);
        let k_perm = subkey(&master, LABEL_PERM);
        assert_ne!(&*k_enc, &*k_mask);
        assert_ne!(&*k_mask, &*k_perm);

        assert_eq!(
            permutation(&[9u8; KEY_LEN], 1_000_000, 5),
            [68594, 274221, 257321, 707829, 526672]
        );
        assert_eq!(hex(&keystream(&[9u8; KEY_LEN], 8)), "f2a76980dfc7a492");
    }

    fn hex(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02x}")).collect()
    }
}
