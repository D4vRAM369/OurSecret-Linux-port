//! Empaqueta varios elementos (archivos y/o mensajes de texto) en un único
//! blob, antes de cifrarlo. El OurSecret original hacía esto con una
//! librería de ZIP pública (XZip/XUnzip, de Lucian Wischik); aquí usamos
//! el crate `zip` de Rust con el mismo objetivo: un único archivo que
//! puede contener varios "items" nombrados.

use std::io::{Cursor, Read, Write};

use zip::write::FileOptions;
use zip::{CompressionMethod, ZipArchive, ZipWriter};

use crate::error::Result;

/// Un elemento a ocultar: o bien un archivo (con su nombre y bytes), o
/// bien un mensaje de texto corto con un "asunto" — igual que el diálogo
/// "Add File or Message" del original, que distinguía entre adjuntar un
/// archivo o escribir un "Instant Message" con Subject + Text.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Item {
    File { name: String, data: Vec<u8> },
    Message { subject: String, text: String },
}

const MESSAGE_PREFIX: &str = "__oursecret_message__/";

/// Empaqueta una lista de items en un zip en memoria.
///
/// Los mensajes de texto se guardan como entradas especiales dentro del
/// zip (prefijo `__oursecret_message__/`) para no necesitar un formato de
/// metadatos aparte — es una decisión deliberadamente simple: todo el
/// "contenedor interno" es, al final, un zip normal y corriente.
pub fn pack(items: &[Item]) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    {
        let mut writer = ZipWriter::new(Cursor::new(&mut buf));
        let options = FileOptions::default().compression_method(CompressionMethod::Deflated);

        for item in items {
            match item {
                Item::File { name, data } => {
                    writer.start_file(name, options)?;
                    writer.write_all(data)?;
                }
                Item::Message { subject, text } => {
                    // Guardamos subject y text como dos líneas: la primera
                    // es el asunto, el resto es el cuerpo del mensaje.
                    let safe_subject = sanitize_filename(subject);
                    let entry_name = format!("{MESSAGE_PREFIX}{safe_subject}.txt");
                    writer.start_file(entry_name, options)?;
                    writer.write_all(subject.as_bytes())?;
                    writer.write_all(b"\n")?;
                    writer.write_all(text.as_bytes())?;
                }
            }
        }
        writer.finish()?;
    }
    Ok(buf)
}

/// Desempaqueta el zip en memoria de vuelta a la lista de items.
pub fn unpack(blob: &[u8]) -> Result<Vec<Item>> {
    let mut archive = ZipArchive::new(Cursor::new(blob))?;
    let mut items = Vec::with_capacity(archive.len());

    for i in 0..archive.len() {
        let mut entry = archive.by_index(i)?;
        // El nombre viene de dentro del contenedor: quien lo creó lo eligió.
        // Nos quedamos solo con el último componente para que
        // `out_dir.join(name)` nunca salga de out_dir ("../x", "/etc/x" — zip-slip).
        let name = std::path::Path::new(entry.name())
            .file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| "archivo".to_string());
        let mut data = Vec::new();
        entry.read_to_end(&mut data)?;

        if entry.name().starts_with(MESSAGE_PREFIX) {
            let text = String::from_utf8_lossy(&data);
            let mut parts = text.splitn(2, '\n');
            let subject = parts.next().unwrap_or_default().to_string();
            let body = parts.next().unwrap_or_default().to_string();
            items.push(Item::Message {
                subject,
                text: body,
            });
        } else {
            items.push(Item::File { name, data });
        }
    }

    Ok(items)
}

fn sanitize_filename(s: &str) -> String {
    s.chars()
        .map(|c| {
            if c.is_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unpack_strips_path_components_from_file_names() {
        let evil = [
            "../escapado.txt",
            "/etc/escapado.txt",
            "a/../../escapado.txt",
        ];
        let items: Vec<Item> = evil
            .iter()
            .map(|n| Item::File {
                name: n.to_string(),
                data: vec![1],
            })
            .collect();
        for item in unpack(&pack(&items).unwrap()).unwrap() {
            assert!(matches!(item, Item::File { ref name, .. } if name == "escapado.txt"));
        }
    }

    #[test]
    fn pack_and_unpack_roundtrip_mixed_items() {
        let items = vec![
            Item::File {
                name: "nota.txt".into(),
                data: b"contenido del archivo".to_vec(),
            },
            Item::Message {
                subject: "Hola".into(),
                text: "Este es un mensaje de prueba\ncon varias lineas".into(),
            },
        ];

        let blob = pack(&items).unwrap();
        let recovered = unpack(&blob).unwrap();

        assert_eq!(recovered.len(), 2);
        assert!(recovered.contains(&items[0]));
        assert!(recovered.contains(&items[1]));
    }
}
