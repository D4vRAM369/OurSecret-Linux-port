use thiserror::Error;

/// Todos los errores que puede devolver `oursecret-core`.
///
/// Por qué un enum y no `anyhow`/`Box<dyn Error>`: la CLI y la futura GUI
/// necesitan distinguir casos concretos (ej. "contraseña incorrecta" debe
/// mostrar un mensaje distinto a "el portador es demasiado pequeño"), así
/// que un error tipado permite `match` en las capas de arriba.
#[derive(Debug, Error)]
pub enum OurSecretError {
    #[error("el archivo portador no tiene espacio suficiente: necesita {needed} bytes, tiene capacidad para {available}")]
    InsufficientCapacity { needed: usize, available: usize },

    #[error("contraseña incorrecta o datos ocultos corruptos")]
    DecryptionFailed,

    #[error("no se encontraron datos ocultos (o la contraseña es incorrecta)")]
    NotAContainer,

    #[error("el modo 'keep same size' (LSB) solo funciona con imágenes PNG o BMP sin comprimir con pérdida; este portador no es una de ellas: {0}")]
    UnsupportedCarrierForLsb(String),

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
