//! Modo LSB (Least Significant Bit): oculta el contenedor cifrado en el
//! bit menos significativo de cada byte de píxel de una imagen PNG o BMP.
//!
//! Por qué solo PNG/BMP: ambos son formatos de compresión *sin pérdida*
//! (o sin compresión, en el caso de BMP). Un formato con pérdida como
//! JPEG reorganiza/aproxima los valores de píxel al comprimir — cualquier
//! bit que escondiéramos ahí se destruiría al guardar el archivo. Esto no
//! es una limitación arbitraria nuestra: es inherente a cómo funciona LSB
//! en general (el OurSecret original probablemente tenía la misma
//! restricción para su modo "keep the same size", aunque no lo hemos
//! podido confirmar — ver docs/06_SIGUIENTE_NIVEL.md).
//!
//! Honestidad sobre el nombre "keep the same size": las *dimensiones* de
//! la imagen (ancho × alto) no cambian. El *tamaño del archivo en bytes*
//! puede variar ligeramente, porque siempre volvemos a guardar como PNG
//! (compresión DEFLATE sin pérdida) y la compresión de una imagen con
//! bits LSB modificados no comprime exactamente igual que el original.

use image::{DynamicImage, ImageBuffer, Rgba};

use crate::error::{OurSecretError, Result};

const LEN_PREFIX_BITS: usize = 32;

/// Cuántos bytes de contenedor caben, como máximo, en esta imagen.
pub fn capacity_bytes(img: &DynamicImage) -> usize {
    let raw_len = img.to_rgba8().into_raw().len();
    raw_len.saturating_sub(LEN_PREFIX_BITS) / 8
}

/// Incrusta `container` en los LSB de `img`. Devuelve la imagen resultante
/// (mismas dimensiones que la original).
pub fn embed(img: &DynamicImage, container: &[u8]) -> Result<DynamicImage> {
    let rgba = img.to_rgba8();
    let (width, height) = rgba.dimensions();
    let mut raw = rgba.into_raw();

    let needed_bits = LEN_PREFIX_BITS + container.len() * 8;
    if needed_bits > raw.len() {
        return Err(OurSecretError::InsufficientCapacity {
            needed: needed_bits.div_ceil(8),
            available: raw.len() / 8,
        });
    }

    // Los primeros 32 bits codifican cuántos bytes de contenedor siguen,
    // para que extract() sepa exactamente dónde parar de leer.
    let len_bits = bits_of_u32(container.len() as u32);
    for (i, bit) in len_bits.iter().enumerate() {
        set_lsb(&mut raw[i], *bit);
    }

    for (byte_idx, &byte) in container.iter().enumerate() {
        for bit_idx in 0..8 {
            let bit = (byte >> (7 - bit_idx)) & 1;
            let pos = LEN_PREFIX_BITS + byte_idx * 8 + bit_idx;
            set_lsb(&mut raw[pos], bit);
        }
    }

    let buf: ImageBuffer<Rgba<u8>, Vec<u8>> = ImageBuffer::from_raw(width, height, raw)
        .expect("el buffer reconstruido tiene el tamaño correcto por construcción");
    Ok(DynamicImage::ImageRgba8(buf))
}

/// Extrae el contenedor previamente incrustado con `embed`.
pub fn extract(img: &DynamicImage) -> Result<Vec<u8>> {
    let raw = img.to_rgba8().into_raw();
    if raw.len() < LEN_PREFIX_BITS {
        return Err(OurSecretError::NotAContainer);
    }

    let mut len_bits = [0u8; LEN_PREFIX_BITS];
    len_bits.copy_from_slice(
        &raw[0..LEN_PREFIX_BITS]
            .iter()
            .map(|b| get_lsb(*b))
            .collect::<Vec<_>>(),
    );
    let container_len = u32_of_bits(&len_bits) as usize;

    let needed_bits = LEN_PREFIX_BITS + container_len * 8;
    if needed_bits > raw.len() {
        // La longitud leída es imposible para esta imagen: no hay datos
        // nuestros aquí (o la imagen fue recomprimida y los bits ya no
        // son los que escondimos).
        return Err(OurSecretError::NotAContainer);
    }

    let mut container = vec![0u8; container_len];
    for (byte_idx, out_byte) in container.iter_mut().enumerate() {
        let mut byte = 0u8;
        for bit_idx in 0..8 {
            let pos = LEN_PREFIX_BITS + byte_idx * 8 + bit_idx;
            byte = (byte << 1) | get_lsb(raw[pos]);
        }
        *out_byte = byte;
    }

    Ok(container)
}

fn set_lsb(byte: &mut u8, bit: u8) {
    *byte = (*byte & 0b1111_1110) | (bit & 1);
}

fn get_lsb(byte: u8) -> u8 {
    byte & 1
}

fn bits_of_u32(value: u32) -> [u8; 32] {
    let mut bits = [0u8; 32];
    for (i, bit) in bits.iter_mut().enumerate() {
        *bit = ((value >> (31 - i)) & 1) as u8;
    }
    bits
}

fn u32_of_bits(bits: &[u8; 32]) -> u32 {
    bits.iter().fold(0u32, |acc, &b| (acc << 1) | b as u32)
}

#[cfg(test)]
mod tests {
    use super::*;
    use image::{GenericImageView, Rgba};

    fn test_image(width: u32, height: u32) -> DynamicImage {
        // Imagen de prueba con algo de variación (no todo el mismo color),
        // para que el test se parezca a un caso real.
        let buf = ImageBuffer::from_fn(width, height, |x, y| {
            Rgba([
                ((x * 7 + y * 3) % 256) as u8,
                (x % 256) as u8,
                (y % 256) as u8,
                255,
            ])
        });
        DynamicImage::ImageRgba8(buf)
    }

    #[test]
    fn embed_then_extract_roundtrip_preserves_dimensions() {
        let img = test_image(64, 64);
        let container = b"contenido secreto de prueba, cifrado en la vida real";

        let stego = embed(&img, container).unwrap();
        assert_eq!(
            stego.dimensions(),
            img.dimensions(),
            "las dimensiones no deben cambiar"
        );

        let recovered = extract(&stego).unwrap();
        assert_eq!(recovered, container);
    }

    #[test]
    fn insufficient_capacity_errors_cleanly() {
        let img = test_image(2, 2); // 2*2*4 canales = 16 bytes de capacidad en bits = 2 bytes útiles
        let too_big = vec![0u8; 1000];
        let err = embed(&img, &too_big).unwrap_err();
        assert!(matches!(err, OurSecretError::InsufficientCapacity { .. }));
    }

    #[test]
    fn capacity_bytes_matches_successful_embed_threshold() {
        let img = test_image(16, 16); // 16*16*4 = 1024 bytes de buffer raw
        let cap = capacity_bytes(&img);
        let exactly_fitting = vec![0xABu8; cap];
        assert!(embed(&img, &exactly_fitting).is_ok());

        let one_too_many = vec![0xABu8; cap + 1];
        assert!(embed(&img, &one_too_many).is_err());
    }
}
