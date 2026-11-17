//! Backend Tauri de la GUI de OurSecret-Linux.
//!
//! Esta capa es deliberadamente delgada: solo traduce entre tipos
//! serializables (para hablar con el frontend JS) y las funciones reales
//! de `oursecret-core`, que es donde vive toda la lógica de verdad. Nada
//! de criptografía, parsing de formato ni esteganografía se implementa
//! aquí — eso ya está hecho, probado y compartido con la CLI.
//!
//! Todos los comandos llevan `#[tauri::command(async)]`: sin `async`, Tauri
//! los ejecuta en el hilo principal (rama `body_blocking` de tauri-macros),
//! y Argon2 + recorrer los píxeles congelaría la ventana mientras dura.

use std::path::PathBuf;

use oursecret_core::{EmbedMode, Item};
use serde::{Deserialize, Serialize};

/// Representación de un `Item` que sí se puede mandar por el puente
/// JSON de Tauri (serde). `oursecret_core::Item` no deriva Serialize
/// porque el core no debería saber nada de cómo se transporta — esta es
/// justo la frontera donde se traduce.
#[derive(Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
enum ItemInput {
    File { path: String },
    Message { subject: String, text: String },
}

#[derive(Serialize)]
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
#[tauri::command(async)]
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
#[tauri::command(async)]
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
    let mut saved = 0;
    for item in items {
        match item {
            Item::File { name, data } => {
                // Si falla a mitad, los anteriores YA están en disco: decirlo.
                let dest = oursecret_core::save_extracted_file(&out_dir_path, &name, &data)
                    .map_err(|e| {
                        format!(
                            "{e} (antes del fallo se guardaron {saved} archivo(s) en {out_dir})"
                        )
                    })?;
                saved += 1;
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

/// Comprueba si `carrier_path` es PNG/BMP y devuelve su capacidad LSB en una
/// sola operación (leyendo solo la cabecera, sin decodificar píxeles).
#[tauri::command(async)]
fn probe_lsb_carrier(carrier_path: String) -> Result<Option<usize>, String> {
    oursecret_core::probe_lsb_capacity(&PathBuf::from(carrier_path)).map_err(|e| e.to_string())
}

/// Tamaño de un archivo a esconder, para la barra "usado / capacidad" de
/// la GUI antes de intentar esconder (y fallar por falta de sitio).
#[tauri::command(async)]
fn file_size(path: String) -> Result<u64, String> {
    std::fs::metadata(&path)
        .map(|m| m.len())
        .map_err(|e| e.to_string())
}

#[cfg_attr(mobile, tauri::mobile_entry_point)]
pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .invoke_handler(tauri::generate_handler![
            hide_items,
            extract_items,
            probe_lsb_carrier,
            file_size
        ])
        .run(tauri::generate_context!())
        .expect("error al arrancar la aplicación Tauri");
}
