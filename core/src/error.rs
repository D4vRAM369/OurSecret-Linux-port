use thiserror::Error;

/// Todos los errores que puede devolver `oursecret-core`.
///
/// Por qué un enum y no `anyhow`/`Box<dyn Error>`: `read` necesita
/// distinguir `DecryptionFailed` de `NotAContainer` para elegir qué error
/// reportar, y los tests comprueban la variante exacta. La CLI y la GUI
/// solo muestran el mensaje (`Display`).
#[derive(Debug, Error)]
pub enum OurSecretError {
    #[error("no cabe en el portador: el contenido, ya empaquetado y cifrado, ocupa {needed} bytes y solo hay sitio para {available}")]
    InsufficientCapacity { needed: usize, available: usize },

    #[error("contraseña incorrecta o datos ocultos corruptos")]
    DecryptionFailed,

    #[error("no se encontraron datos ocultos (o la contraseña es incorrecta)")]
    NotAContainer,

    #[error("el modo LSB solo funciona con imágenes PNG o BMP y este portador no lo es (usa el modo append): {0}")]
    UnsupportedCarrierForLsb(String),

    #[error("{0}")]
    InvalidInput(&'static str),

    #[error("el contenido oculto se descomprime a más de {limit} bytes (posible zip bomb); extracción detenida")]
    DecompressionLimit { limit: u64 },

    #[error("error de E/S: {0}")]
    Io(#[from] std::io::Error),

    #[error("error empaquetando/desempaquetando el zip interno: {0}")]
    Zip(#[from] zip::result::ZipError),

    #[error("error decodificando la imagen portadora: {0}")]
    Image(#[from] image::ImageError),

    #[error("error derivando la clave desde la contraseña: {0}")]
    Kdf(String),
}

pub type Result<T> = std::result::Result<T, OurSecretError>;
