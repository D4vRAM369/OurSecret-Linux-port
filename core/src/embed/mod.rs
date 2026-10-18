//! Estrategias de inserción del contenedor cifrado dentro de un archivo
//! portador. Corresponden a los dos "modales" que vimos en la interfaz
//! del OurSecret original: *"Hide more data"* (el portador crece) y *"Keep the same size"* (no
//! crece). No sabemos el algoritmo exacto que usaba el original por
//! dentro (bloqueado por su protector), así que estas son implementaciones
//! propias que logran el mismo *efecto observable*.

pub mod append;
pub mod lsb;

/// Qué estrategia de inserción usar.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EmbedMode {
    /// Añade el contenedor al final de cualquier archivo portador. Simple,
    /// funciona con cualquier tipo de archivo, pero el archivo resultante
    /// pesa más que el original — equivalente a "Hide more data".
    Append,
    /// Oculta el contenedor en los bits menos significativos de los
    /// píxeles de una imagen PNG/BMP. El archivo resultante tiene las
    /// mismas dimensiones de imagen (no "crece" en contenido visual),
    /// pero solo funciona con imágenes y tiene una capacidad limitada por
    /// su tamaño — equivalente a "Keep the same size".
    Lsb,
}
