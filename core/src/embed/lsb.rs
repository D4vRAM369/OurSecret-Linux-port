//! Modo LSB (Least Significant Bit): oculta el contenedor cifrado en el
//! bit menos significativo de los bytes de píxel de una imagen PNG o BMP.
//!
//! # Formato v2 (actual, más difícil de detectar)
//!
//! Tres mejoras sobre el v1 respecto a la detectabilidad (ver
//! `docs/informes/2026-10-17-auditoria-superficie-sin-clave.md`):
//!
//! 1. **Solo RGB, nunca alfa.** El v1 pasaba la imagen a RGBA y escribía
//!    también en el canal alfa; una foto opaca que de repente tiene alfa
//!    con valores ≠255 es una señal obvia. El v2 trabaja sobre los 3
//!    canales de color y deja la imagen en RGB.
//! 2. **Longitud cifrada.** El v1 escribía la longitud del contenido en
//!    claro en los primeros 32 LSB. El v2 la guarda XOR una máscara
//!    derivada de la clave → parece ruido.
//! 3. **Posiciones derivadas de la clave.** El v1 insertaba de forma
//!    secuencial (desde el píxel 0), lo que el ataque chi-cuadrado por
//!    prefijos detecta y ubica. El v2 dispersa los bits por toda la imagen
//!    según una permutación que solo puede reconstruir quien tiene la
//!    contraseña.
//!
//! Distribución de las posiciones LSB (sobre los bytes RGB de la imagen):
//!
//! ```text
//! posiciones 0..128     sal (16 bytes) en claro — es pública, parece ruido
//! posiciones 128..160   longitud del payload (u32) XOR máscara de clave
//! posiciones 160..N     payload (nonce|ciphertext) en orden permutado por clave
//! ```
//!
//! Qué NO esconde el v2 (honestidad): el *número total* de bits LSB
//! modificados sigue siendo estimable con análisis RS si la carga es alta
//! — contra eso solo ayudan cargas pequeñas o ±1 matching, que no se
//! implementan aquí. Lo que el v2 rompe es la detección por firma, por
//! longitud en claro, por canal alfa y por chi-cuadrado secuencial.
//!
//! # Formato v1 (solo lectura)
//!
//! Longitud en claro (32 bits) + contenedor con magia, sobre RGBA
//! secuencial. Se intenta al leer si el v2 no encaja.

use image::{DynamicImage, ImageBuffer, Rgb};

use crate::crypto::{self, KEY_LEN, NONCE_LEN, SALT_LEN};
use crate::error::{OurSecretError, Result};

const SALT_BITS: usize = SALT_LEN * 8; // 128
const LEN_BITS: usize = 32;
const OVERHEAD_BITS: usize = SALT_BITS + LEN_BITS; // 160
/// Mínimo payload v2 = nonce + tag GCM.
const MIN_PAYLOAD: usize = NONCE_LEN + crate::format::GCM_TAG_LEN;

/// Cuántos bytes de payload (nonce|ciphertext) caben, como máximo, en esta
/// imagen con el formato v2. El contenedor interno (el zip) será algo menor,
/// porque el cifrado añade nonce (12) + tag (16).
pub fn capacity_bytes(img: &DynamicImage) -> usize {
    let raw_len = img.to_rgb8().into_raw().len();
    raw_len.saturating_sub(OVERHEAD_BITS) / 8
}

/// Incrusta `plain_blob` en los LSB de `img` (formato v2). Devuelve la
/// imagen resultante, mismas dimensiones, en RGB.
pub fn embed(img: &DynamicImage, plain_blob: &[u8], password: &str) -> Result<DynamicImage> {
    let rgb = img.to_rgb8();
    let (width, height) = rgb.dimensions();
    let mut raw = rgb.into_raw();

    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let key = crypto::derive_key(password, &salt)?;
    let ciphertext = crypto::encrypt(&key, &nonce, plain_blob)?;

    // payload = nonce || ciphertext (lo que se dispersa por la imagen).
    let mut payload = Vec::with_capacity(NONCE_LEN + ciphertext.len());
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);

    let needed_bits = OVERHEAD_BITS + payload.len() * 8;
    if needed_bits > raw.len() {
        return Err(OurSecretError::InsufficientCapacity {
            needed: needed_bits.div_ceil(8),
            available: raw.len() / 8,
        });
    }

    // 1) sal en claro en las primeras 128 posiciones.
    for (i, bit) in bits_of_bytes(&salt).enumerate() {
        set_lsb(&mut raw[i], bit);
    }

    // 2) longitud del payload (u32) XOR máscara de clave, posiciones 128..160.
    let len_enc = (payload.len() as u32) ^ mask_u32(&key);
    for (i, bit) in bits_of_u32(len_enc).into_iter().enumerate() {
        set_lsb(&mut raw[SALT_BITS + i], bit);
    }

    // 3) payload en posiciones permutadas dentro de [160..N).
    let perm = crypto::permutation(&key, raw.len() - OVERHEAD_BITS);
    let mut bit_idx = 0;
    for &byte in &payload {
        for b in (0..8).rev() {
            let pos = OVERHEAD_BITS + perm[bit_idx] as usize;
            set_lsb(&mut raw[pos], (byte >> b) & 1);
            bit_idx += 1;
        }
    }

    let buf: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_raw(width, height, raw)
        .expect("el buffer reconstruido tiene el tamaño correcto por construcción");
    Ok(DynamicImage::ImageRgb8(buf))
}

/// Extrae y descifra el contenido incrustado (v2). Si no encaja como v2,
/// intenta el formato v1 antiguo. Devuelve el `plain_blob`.
pub fn extract(img: &DynamicImage, password: &str) -> Result<Vec<u8>> {
    match extract_v2(img, password) {
        Err(OurSecretError::NotAContainer) => extract_v1(img, password),
        other => other,
    }
}

fn extract_v2(img: &DynamicImage, password: &str) -> Result<Vec<u8>> {
    let raw = img.to_rgb8().into_raw();
    if raw.len() < OVERHEAD_BITS {
        return Err(OurSecretError::NotAContainer);
    }

    // 1) sal (pública) → clave.
    let mut salt = [0u8; SALT_LEN];
    for (i, b) in salt.iter_mut().enumerate() {
        let mut v = 0u8;
        for k in 0..8 {
            v = (v << 1) | get_lsb(raw[i * 8 + k]);
        }
        *b = v;
    }
    let key = crypto::derive_key(password, &salt)?;

    // 2) longitud cifrada.
    let mut len_bits = [0u8; LEN_BITS];
    for (i, bit) in len_bits.iter_mut().enumerate() {
        *bit = get_lsb(raw[SALT_BITS + i]);
    }
    let payload_len = (u32_of_bits(&len_bits) ^ mask_u32(&key)) as usize;

    // Si la longitud no cabe o es absurda: no es nuestro (o clave mala).
    let avail = raw.len() - OVERHEAD_BITS;
    if payload_len < MIN_PAYLOAD || payload_len * 8 > avail {
        return Err(OurSecretError::NotAContainer);
    }

    // 3) payload desde las posiciones permutadas.
    let perm = crypto::permutation(&key, avail);
    let mut payload = vec![0u8; payload_len];
    let mut bit_idx = 0;
    for out_byte in payload.iter_mut() {
        let mut v = 0u8;
        for _ in 0..8 {
            let pos = OVERHEAD_BITS + perm[bit_idx] as usize;
            v = (v << 1) | get_lsb(raw[pos]);
            bit_idx += 1;
        }
        *out_byte = v;
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload[..NONCE_LEN]);
    let ciphertext = &payload[NONCE_LEN..];
    crypto::decrypt(&key, &nonce, ciphertext)
}

/// Lectura del formato v1 (RGBA, longitud en claro, contenedor con magia).
fn extract_v1(img: &DynamicImage, password: &str) -> Result<Vec<u8>> {
    const LEN_PREFIX_BITS: usize = 32;
    let raw = img.to_rgba8().into_raw();
    if raw.len() < LEN_PREFIX_BITS {
        return Err(OurSecretError::NotAContainer);
    }
    let mut len_bits = [0u8; LEN_PREFIX_BITS];
    for (i, bit) in len_bits.iter_mut().enumerate() {
        *bit = get_lsb(raw[i]);
    }
    let container_len = u32_of_bits(&len_bits) as usize;
    if LEN_PREFIX_BITS + container_len * 8 > raw.len() {
        return Err(OurSecretError::NotAContainer);
    }
    let mut container = vec![0u8; container_len];
    for (byte_idx, out_byte) in container.iter_mut().enumerate() {
        let mut byte = 0u8;
        for bit_idx in 0..8 {
            byte = (byte << 1) | get_lsb(raw[LEN_PREFIX_BITS + byte_idx * 8 + bit_idx]);
        }
        *out_byte = byte;
    }
    crate::format::open_container(&container, password)
}

fn mask_u32(key: &[u8; KEY_LEN]) -> u32 {
    let ks = crypto::keystream(key, 4);
    u32::from_le_bytes(ks.try_into().unwrap())
}

fn set_lsb(byte: &mut u8, bit: u8) {
    *byte = (*byte & 0b1111_1110) | (bit & 1);
}

fn get_lsb(byte: u8) -> u8 {
    byte & 1
}

fn bits_of_bytes(bytes: &[u8]) -> impl Iterator<Item = u8> + '_ {
    bytes
        .iter()
        .flat_map(|&b| (0..8).rev().map(move |i| (b >> i) & 1))
}

fn bits_of_u32(value: u32) -> [u8; 32] {
    let mut bits = [0u8; 32];
    for (i, bit) in bits.iter_mut().enumerate() {
        *bit = ((value >> (31 - i)) & 1) as u8;
    }
    bits
}

fn u32_of_bits(bits: &[u8]) -> u32 {
    bits.iter().fold(0u32, |acc, &b| (acc << 1) | b as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::GenericImageView;
    use image::Rgb as RgbPix;

    fn test_image(width: u32, height: u32) -> DynamicImage {
        let buf = ImageBuffer::from_fn(width, height, |x, y| {
            RgbPix([
                ((x * 7 + y * 3) % 256) as u8,
                (x % 256) as u8,
                (y % 256) as u8,
            ])
        });
        DynamicImage::ImageRgb8(buf)
    }

    #[test]
    fn embed_then_extract_roundtrip_preserves_dimensions() {
        let img = test_image(64, 64);
        let plain = b"contenido secreto de prueba, cifrado en la vida real";

        let stego = embed(&img, plain, "clave").unwrap();
        assert_eq!(stego.dimensions(), img.dimensions());
        assert!(
            matches!(stego, DynamicImage::ImageRgb8(_)),
            "la salida no debe tener canal alfa"
        );

        let recovered = extract(&stego, "clave").unwrap();
        assert_eq!(recovered, plain);
    }

    #[test]
    fn wrong_password_does_not_return_garbage() {
        let img = test_image(64, 64);
        let stego = embed(&img, b"secreto", "buena").unwrap();
        assert!(extract(&stego, "mala").is_err());
    }

    #[test]
    fn insufficient_capacity_errors_cleanly() {
        let img = test_image(4, 4); // 4*4*3 = 48 bytes; overhead 160 bits = 20 bytes
        let err = embed(&img, &vec![0u8; 1000], "k").unwrap_err();
        assert!(matches!(err, OurSecretError::InsufficientCapacity { .. }));
    }

    #[test]
    fn capacity_matches_embed_threshold() {
        let img = test_image(16, 16); // 16*16*3 = 768 bytes raw
        let cap = capacity_bytes(&img); // payload máximo
        // Un plain_blob que, cifrado, deja el payload justo en el límite:
        // payload = 12 (nonce) + plain + 16 (tag). cap = payload máximo.
        let plain = vec![0xABu8; cap - NONCE_LEN - crate::format::GCM_TAG_LEN];
        assert!(embed(&img, &plain, "k").is_ok());
        let too_big = vec![0xABu8; cap]; // payload > cap seguro
        assert!(embed(&img, &too_big, "k").is_err());
    }
}
