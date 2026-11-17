//! Modo LSB (Least Significant Bit): oculta el contenedor cifrado en el
//! bit menos significativo de los bytes de píxel de una imagen PNG o BMP.
//!
//! # Formato (difícil de detectar)
//!
//! Cuatro decisiones contra la detección (motivadas por una auditoría de
//! un primer formato ya retirado):
//!
//! 1. **Solo RGB, nunca alfa.** Una foto opaca que de repente tiene alfa
//!    con valores ≠255 es una señal obvia. Se trabaja sobre los 3 canales
//!    de color y la imagen se queda en RGB.
//! 2. **Longitud cifrada.** La longitud se guarda XOR una máscara derivada
//!    de la clave → parece ruido.
//! 3. **Posiciones derivadas de la clave.** Insertar de forma secuencial
//!    (desde el píxel 0) lo detecta y ubica el ataque chi-cuadrado por
//!    prefijos. Aquí los bits se dispersan por toda la imagen según una
//!    permutación que solo puede reconstruir quien tiene la contraseña.
//!
//! Distribución de las posiciones LSB (sobre los bytes RGB de la imagen):
//!
//! ```text
//! posiciones 0..128     sal (16 bytes) en claro — es pública, parece ruido
//! posiciones 128..160   longitud del payload (u32) XOR máscara de clave
//! posiciones 160..N     payload (nonce|ciphertext) en orden permutado por clave
//! ```
//!
//! 4. **±1 matching** en vez de reemplazar el bit (ver `set_lsb`). Medido:
//!    el análisis RS pasa de estimar la carga casi exacta (0,93 con la
//!    imagen al 95 %) a dar lo mismo que la imagen limpia (≈0).
//!
//! Qué NO esconde (honestidad): ±1 matching también deja huella, solo que
//! más sutil (suaviza el histograma). Hay detectores específicos para él
//! (función característica del histograma, calibración, modelos tipo SPAM
//! o redes neuronales entrenadas), y funcionan mejor cuanto más alta es la
//! carga. Lo más eficaz sigue siendo esconder poco en imágenes grandes.

use image::{DynamicImage, ImageBuffer, Rgb};

use crate::crypto::{
    self, GCM_TAG_LEN, KEY_LEN, LABEL_ENC, LABEL_MASK, LABEL_PERM, NONCE_LEN, SALT_LEN,
};
use crate::error::{OurSecretError, Result};

const SALT_BITS: usize = SALT_LEN * 8; // 128
const LEN_BITS: usize = 32;
const OVERHEAD_BITS: usize = SALT_BITS + LEN_BITS; // 160
/// Mínimo payload = nonce + tag GCM.
const MIN_PAYLOAD: usize = NONCE_LEN + GCM_TAG_LEN;

/// Cuántos bytes de payload (nonce|ciphertext) caben, como máximo, en esta
/// imagen. El contenedor interno (el zip) será algo menor,
/// porque el cifrado añade nonce (12) + tag (16).
pub fn capacity_bytes(img: &DynamicImage) -> usize {
    let raw_len = img.to_rgb8().into_raw().len();
    raw_len.saturating_sub(OVERHEAD_BITS) / 8
}

/// Igual que [`capacity_bytes`], pero a partir de las dimensiones sin
/// decodificar todos los píxeles de la imagen en memoria.
pub fn capacity_bytes_for_dimensions(width: u32, height: u32) -> usize {
    let raw_len = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(3);
    raw_len.saturating_sub(OVERHEAD_BITS) / 8
}

/// Posiciones públicas deterministas para la cabecera (`salt || len_enc`,
/// 160 bits) dispersadas por toda la imagen según `raw.len()`.
///
/// Por qué (formato v3): concentrar los 160 bits siempre en `raw[0..160]`
/// creaba una densidad de modificación del ~50 % en los primeros ~54 píxeles
/// de la esquina superior izquierda aunque el secreto fuese diminuto.
fn header_positions(raw_len: usize) -> Vec<usize> {
    let seed = crypto::hash_seed(&[b"oursecret-v3-lsb-header", &(raw_len as u64).to_le_bytes()]);
    crypto::permutation(&seed, raw_len, OVERHEAD_BITS)
}

/// Biyección estrictamente creciente de `0..(raw_len - OVERHEAD_BITS)` al
/// conjunto de índices físicos en `0..raw_len` que NO están en `sorted_hdr`.
fn map_non_header(logical_idx: usize, sorted_hdr: &[usize]) -> usize {
    let mut phys = logical_idx;
    for &h in sorted_hdr {
        if h <= phys {
            phys += 1;
        } else {
            break;
        }
    }
    phys
}

fn build_lsb_aad(salt: &[u8; SALT_LEN], len_enc: u32) -> [u8; SALT_LEN + 4] {
    let mut aad = [0u8; SALT_LEN + 4];
    aad[..SALT_LEN].copy_from_slice(salt);
    aad[SALT_LEN..].copy_from_slice(&len_enc.to_le_bytes());
    aad
}

/// Incrusta `plain_blob` en los LSB de `img`. Devuelve la
/// imagen resultante, mismas dimensiones, en RGB.
pub fn embed(img: &DynamicImage, plain_blob: &[u8], password: &str) -> Result<DynamicImage> {
    let rgb = img.to_rgb8();
    let (width, height) = rgb.dimensions();
    let mut raw = rgb.into_raw();

    // Comprobación de capacidad antes de derivar la clave (si no cabe ni la
    // cabecera o el payload, fallamos rápido sin gastar Argon2id).
    let expected_payload_len = NONCE_LEN + plain_blob.len() + GCM_TAG_LEN;
    let payload_len_u32 =
        u32::try_from(expected_payload_len).map_err(|_| OurSecretError::InsufficientCapacity {
            needed: expected_payload_len + OVERHEAD_BITS.div_ceil(8),
            available: raw.len() / 8,
        })?;
    let needed_bits = OVERHEAD_BITS + expected_payload_len * 8;
    if needed_bits > raw.len() {
        return Err(OurSecretError::InsufficientCapacity {
            needed: needed_bits.div_ceil(8),
            available: raw.len() / 8,
        });
    }

    let salt = crypto::random_salt();
    let nonce = crypto::random_nonce();
    let master = crypto::derive_key(password, &salt)?;
    let k_enc = crypto::subkey(&master, LABEL_ENC);
    let k_mask = crypto::subkey(&master, LABEL_MASK);
    let k_perm = crypto::subkey(&master, LABEL_PERM);

    let len_enc = payload_len_u32 ^ mask_u32(&k_mask);
    let aad = build_lsb_aad(&salt, len_enc);
    let ciphertext = crypto::encrypt(&k_enc, &nonce, plain_blob, &aad)?;
    debug_assert_eq!(NONCE_LEN + ciphertext.len(), expected_payload_len);

    // payload = nonce || ciphertext (lo que se dispersa por la imagen).
    let mut payload = Vec::with_capacity(expected_payload_len);
    payload.extend_from_slice(&nonce);
    payload.extend_from_slice(&ciphertext);

    // 1) Cabecera (sal + longitud enmascarada) en 160 posiciones dispersas por toda la imagen.
    let hdr_pos = header_positions(raw.len());
    for (i, bit) in bits_of_bytes(&salt).enumerate() {
        set_lsb(&mut raw[hdr_pos[i]], bit);
    }
    for (i, bit) in bits_of_u32(len_enc).into_iter().enumerate() {
        set_lsb(&mut raw[hdr_pos[SALT_BITS + i]], bit);
    }

    // 2) Payload en posiciones permutadas dentro de los índices restantes.
    let mut sorted_hdr = hdr_pos;
    sorted_hdr.sort_unstable();
    let perm = crypto::permutation(&k_perm, raw.len() - OVERHEAD_BITS, payload.len() * 8);
    let mut bit_idx = 0;
    for &byte in &payload {
        for b in (0..8).rev() {
            let pos = map_non_header(perm[bit_idx], &sorted_hdr);
            set_lsb(&mut raw[pos], (byte >> b) & 1);
            bit_idx += 1;
        }
    }

    let buf: ImageBuffer<Rgb<u8>, Vec<u8>> = ImageBuffer::from_raw(width, height, raw)
        .expect("el buffer reconstruido tiene el tamaño correcto por construcción");
    Ok(DynamicImage::ImageRgb8(buf))
}

/// Extrae y descifra el contenido incrustado. Devuelve el `plain_blob`.
pub fn extract(img: &DynamicImage, password: &str) -> Result<Vec<u8>> {
    let raw = img.to_rgb8().into_raw();
    if raw.len() < OVERHEAD_BITS {
        return Err(OurSecretError::NotAContainer);
    }

    let hdr_pos = header_positions(raw.len());

    // 1) sal (pública) → subclaves.
    let mut salt = [0u8; SALT_LEN];
    for (i, b) in salt.iter_mut().enumerate() {
        let mut v = 0u8;
        for k in 0..8 {
            v = (v << 1) | get_lsb(raw[hdr_pos[i * 8 + k]]);
        }
        *b = v;
    }
    let master = crypto::derive_key(password, &salt)?;
    let k_mask = crypto::subkey(&master, LABEL_MASK);
    let k_perm = crypto::subkey(&master, LABEL_PERM);
    let k_enc = crypto::subkey(&master, LABEL_ENC);

    // 2) longitud cifrada.
    let mut len_bits = [0u8; LEN_BITS];
    for (i, bit) in len_bits.iter_mut().enumerate() {
        *bit = get_lsb(raw[hdr_pos[SALT_BITS + i]]);
    }
    let len_enc = u32_of_bits(&len_bits);
    let payload_len = (len_enc ^ mask_u32(&k_mask)) as usize;

    // Si la longitud no cabe o es absurda: no es nuestro (o clave mala).
    let avail = raw.len() - OVERHEAD_BITS;
    if payload_len < MIN_PAYLOAD || payload_len > avail / 8 {
        return Err(OurSecretError::NotAContainer);
    }

    // 3) payload desde las posiciones permutadas (excluyendo la cabecera).
    let mut sorted_hdr = hdr_pos;
    sorted_hdr.sort_unstable();
    let perm = crypto::permutation(&k_perm, avail, payload_len * 8);
    let mut payload = vec![0u8; payload_len];
    let mut bit_idx = 0;
    for out_byte in payload.iter_mut() {
        let mut v = 0u8;
        for _ in 0..8 {
            let pos = map_non_header(perm[bit_idx], &sorted_hdr);
            v = (v << 1) | get_lsb(raw[pos]);
            bit_idx += 1;
        }
        *out_byte = v;
    }

    let mut nonce = [0u8; NONCE_LEN];
    nonce.copy_from_slice(&payload[..NONCE_LEN]);
    let ciphertext = &payload[NONCE_LEN..];
    let aad = build_lsb_aad(&salt, len_enc);
    crypto::decrypt(&k_enc, &nonce, ciphertext, &aad)
}

fn mask_u32(mask_seed: &[u8; KEY_LEN]) -> u32 {
    let ks = crypto::keystream(mask_seed, 4);
    u32::from_le_bytes(ks.try_into().unwrap())
}

/// LSB *matching* (±1), no LSB *replacement*. Si el último bit ya es el
/// que queremos, no se toca nada. Si no, se suma o resta 1 al azar (en
/// 0 solo se puede sumar, en 255 solo restar). Las dos opciones cambian el
/// último bit igual, así que `get_lsb` lee lo mismo: la extracción no cambia.
///
/// Por qué: reemplazar el bit solo mueve valores dentro de su pareja
/// (2k ↔ 2k+1), y eso deja una huella que el análisis RS y el
/// chi-cuadrado miden (las parejas se "igualan"). Con ±1, un 2k puede
/// irse a 2k−1, que es de otra pareja, y esa simetría desaparece.
///
/// El azar del ±1 no sale de la clave: no hace falta reproducirlo al leer,
/// y así no aporta ninguna pista sobre ella.
fn set_lsb(byte: &mut u8, bit: u8) {
    if *byte & 1 == bit & 1 {
        return;
    }
    *byte = match *byte {
        0 => 1,
        255 => 254,
        b if rand::random::<bool>() => b + 1,
        b => b - 1,
    };
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
    fn set_lsb_is_plus_minus_one_and_uses_both_directions() {
        for v in 0..=255u8 {
            for bit in 0..=1u8 {
                let mut b = v;
                set_lsb(&mut b, bit);
                assert_eq!(get_lsb(b), bit, "v={v} bit={bit}");
                assert!(b.abs_diff(v) <= 1, "v={v} -> {b}: más de ±1");
                if v & 1 == bit {
                    assert_eq!(b, v, "si el bit ya coincide no se toca");
                }
            }
        }
        // Con 200 intentos, que salgan siempre +1 (o siempre −1) tiene
        // probabilidad 2^-199: si pasa, el azar no funciona.
        let results: std::collections::HashSet<u8> = (0..200)
            .map(|_| {
                let mut b = 100u8;
                set_lsb(&mut b, 1);
                b
            })
            .collect();
        assert_eq!(results, [99u8, 101].into_iter().collect());
    }

    /// Imagen cuyos LSB dicen: sal = ceros, longitud descifrada con "pw" =
    /// `claimed`. El resto de píxeles, basura. Así se prueban los valores
    /// límite *después* de la KDF, que bytes al azar casi nunca alcanzan.
    fn crafted(w: u32, h: u32, mask_key: &[u8; KEY_LEN], claimed: u32) -> DynamicImage {
        let mut raw: Vec<u8> = (0..w * h * 3).map(|i| (i * 37 % 251) as u8).collect();
        let hdr_pos = header_positions(raw.len());
        for &p in hdr_pos.iter().take(SALT_BITS) {
            raw[p] &= 0b1111_1110; // sal = 16 bytes a cero
        }
        for (i, bit) in bits_of_u32(claimed ^ mask_u32(mask_key))
            .into_iter()
            .enumerate()
        {
            let p = hdr_pos[SALT_BITS + i];
            raw[p] = (raw[p] & 0b1111_1110) | bit;
        }
        DynamicImage::ImageRgb8(ImageBuffer::from_raw(w, h, raw).unwrap())
    }

    #[test]
    fn hostile_input_errors_instead_of_panicking() {
        // Demasiado pequeñas para la cabecera (160 bits): error antes de la KDF.
        for (w, h) in [(0, 0), (1, 1), (7, 7)] {
            let img = DynamicImage::ImageRgb8(ImageBuffer::new(w, h));
            assert!(extract(&img, "pw").is_err(), "{w}x{h}");
        }

        let master = crypto::derive_key("pw", &[0u8; SALT_LEN]).unwrap();
        let mask_key = crypto::subkey(&master, LABEL_MASK);
        let (w, h) = (20u32, 20u32);
        let max = ((w * h * 3) as usize - OVERHEAD_BITS) / 8; // payload máximo que cabe
        for claimed in [
            0,
            MIN_PAYLOAD as u32 - 1,
            MIN_PAYLOAD as u32, // pasa el filtro → GCM rechaza la basura
            max as u32,         // justo en el límite → idem
            max as u32 + 1,     // un byte de más
            u32::MAX,           // ×8 desbordaría en 32 bits
        ] {
            let err = extract(&crafted(w, h, &mask_key, claimed), "pw").unwrap_err();
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
        // 16*16*3 = 768 bytes raw.
        let img = test_image(16, 16);
        // cap = payload máximo. Un plain_blob que, cifrado, lo deja justo en
        // el límite: payload = 12 (nonce) + plain + 16 (tag).
        let cap = capacity_bytes(&img);
        let plain = vec![0xABu8; cap - NONCE_LEN - GCM_TAG_LEN];
        assert!(embed(&img, &plain, "k").is_ok());
        let too_big = vec![0xABu8; cap]; // payload > cap seguro
        assert!(embed(&img, &too_big, "k").is_err());
    }
}
