//! Backend Tauri de la GUI de OurSecret-Linux.
//!
//! Esta capa es deliberadamente delgada: solo traduce entre tipos
//! serializables (para hablar con el frontend JS) y las funciones reales
//! de `oursecret-core`, que es donde vive toda la lógica de verdad. Nada
//! de criptografía, parsing de formato ni esteganografía se implementa
//! aquí — eso ya está hecho, probado y compartido con la CLI.

use std::path::PathBuf;

use oursecret_core::{EmbedMode, Item};
use serde::{Deserialize, Serialize};

/// Representación de un `Item` que sí se puede mandar por el puente
/// JSON de Tauri (serde). `oursecret_core::Item` no deriva Serialize
/// porque el core no debería saber nada de cómo se transporta — esta es
/// justo la frontera donde se traduce.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ItemInput {
    File { path: String },
    Message { subject: String, text: String },
}

#[derive(Debug, Clone, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ExtractedItem {
    File { name: String, saved_to: String },
    Message { subject: String, text: String },
}

fn to_core_item(input: ItemInput) -> Result<Item, String> {
    match input {
        ItemInput::File { path } => {
            let p = PathBuf::from(&path);
            let data = std::fs::read(&p).map_err(|e| format!("leyendo {path}: {e}"))?;
            let name = p
                .file_name()
                .map(|n| n.to_string_lossy().to_string())
                .unwrap_or_else(|| "archivo".to_string());
            Ok(Item::File { name, data })
        }
        ItemInput::Message { subject, text } => Ok(Item::Message { subject, text }),
    }
}

/// Paso 2+3 del flujo original ("añadir archivo/mensaje" + "contraseña")
/// hechos en una sola llamada: empaqueta, cifra y esconde en `carrier_path`.
#[tauri::command]
fn hide_items(
    carrier_path: String,
    output_path: String,
    items: Vec<ItemInput>,
    password: String,
    mode: String,
) -> Result<(), String> {
    if items.is_empty() {
        return Err("no hay nada que esconder: añade al menos un archivo o un mensaje".into());
    }

    let embed_mode = match mode.as_str() {
        "append" => EmbedMode::Append,
        "lsb" => EmbedMode::Lsb,
        other => return Err(format!("modo desconocido: {other}")),
    };

    let core_items: Vec<Item> = items
        .into_iter()
        .map(to_core_item)
        .collect::<Result<_, _>>()?;

    oursecret_core::hide(
        &PathBuf::from(&carrier_path),
        &core_items,
        &password,
        embed_mode,
        &PathBuf::from(&output_path),
    )
    .map_err(|e| e.to_string())
}

/// Paso 1+2 del flujo de lectura ("abrir stegano-media" + "contraseña"):
/// descifra y, para los archivos, los escribe en `out_dir`.
#[tauri::command]
fn extract_items(
    input_path: String,
    out_dir: String,
    password: String,
) -> Result<Vec<ExtractedItem>, String> {
    let items =
        oursecret_core::read(&PathBuf::from(&input_path), &password).map_err(|e| e.to_string())?;

    let out_dir_path = PathBuf::from(&out_dir);
    std::fs::create_dir_all(&out_dir_path).map_err(|e| e.to_string())?;

    let mut result = Vec::with_capacity(items.len());
    for item in items {
        match item {
            Item::File { name, data } => {
                let dest = oursecret_core::save_extracted_file(&out_dir_path, &name, &data)
                    .map_err(|e| e.to_string())?;
                result.push(ExtractedItem::File {
                    name,
                    saved_to: dest.to_string_lossy().to_string(),
                });
            }
            Item::Message { subject, text } => {
                result.push(ExtractedItem::Message { subject, text });
            }
        }
    }
    Ok(result)
}

/// Para el modo LSB: cuántos bytes caben en esta imagen, para avisar al
/// usuario antes de que intente esconder algo demasiado grande.
#[tauri::command]
fn lsb_capacity(carrier_path: String) -> Result<usize, String> {
    let img = image::open(&carrier_path).map_err(|e| e.to_string())?;
    Ok(oursecret_core::embed::lsb::capacity_bytes(&img))
}

/// Si `carrier_path` es una imagen PNG/BMP válida — decide si ofrecer el
/// modo LSB en la interfaz o dejar solo el modo `append`.
#[tauri::command]
fn is_image_carrier(carrier_path: String) -> bool {
    image::open(&carrier_path).is_ok()
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_opener::init())
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            hide_items,
            extract_items,
            lsb_capacity,
            is_image_carrier
        ])
        .run(tauri::generate_context!())
        .expect("error while running tauri application");
}
