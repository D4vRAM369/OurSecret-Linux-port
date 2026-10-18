//! CLI del port Linux de OurSecret.
//!
//! Replica, en línea de comandos, el flujo de 3 pasos del programa
//! original (elegir portador → añadir archivos/mensaje → contraseña) sin
//! usar ninguno de sus algoritmos propietarios — el diseño está en
//! `oursecret-core`.

use std::path::PathBuf;

use anyhow::{bail, Context, Result};
use clap::{Parser, Subcommand};
use oursecret_core::{EmbedMode, Item};

#[derive(Parser)]
#[command(name = "oursecret", version, about = "Esteganografía + cifrado: esconde archivos o mensajes dentro de otro archivo", long_about = None)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Esconde uno o varios archivos y/o un mensaje de texto dentro de un archivo portador.
    Hide {
        /// Archivo portador (la "tapadera"). Con --mode lsb debe ser PNG o BMP.
        #[arg(short, long)]
        carrier: PathBuf,

        /// Dónde escribir el archivo resultante.
        #[arg(short, long)]
        output: PathBuf,

        /// Archivo(s) a esconder. Se puede repetir.
        #[arg(short, long = "file")]
        files: Vec<PathBuf>,

        /// Mensaje de texto a esconder, formato "asunto:texto". Se puede repetir.
        #[arg(short, long = "message")]
        messages: Vec<String>,

        /// Estrategia de ocultación: "append" (cualquier archivo, crece de tamaño)
        /// o "lsb" (solo imágenes PNG/BMP, mantiene las dimensiones).
        /// Ojo: con "append", en PNG/JPEG/PDF/ZIP se ve que sobran datos tras
        /// el final del archivo (no qué son, pero sí que hay algo); en audio y
        /// vídeo se nota menos. Para fotos, "lsb" es más discreto.
        #[arg(long, default_value = "append")]
        mode: String,

        /// Contraseña. Si se omite, se pide de forma interactiva (recomendado:
        /// pasarla por flag la deja visible en el historial de la shell).
        #[arg(short, long)]
        password: Option<String>,
    },

    /// Extrae y descifra lo escondido en un archivo generado con `hide`.
    Extract {
        /// Archivo con datos ocultos.
        #[arg(short, long)]
        input: PathBuf,

        /// Carpeta donde guardar los archivos extraídos (se crea si no existe).
        #[arg(short, long, default_value = ".")]
        out_dir: PathBuf,

        #[arg(short, long)]
        password: Option<String>,
    },

    /// Para el modo LSB: cuántos bytes caben escondidos en esta imagen.
    Capacity {
        #[arg(short, long)]
        carrier: PathBuf,
    },
}

fn main() -> Result<()> {
    let cli = Cli::parse();
    match cli.command {
        Command::Hide {
            carrier,
            output,
            files,
            messages,
            mode,
            password,
        } => cmd_hide(carrier, output, files, messages, &mode, password),
        Command::Extract {
            input,
            out_dir,
            password,
        } => cmd_extract(input, out_dir, password),
        Command::Capacity { carrier } => cmd_capacity(carrier),
    }
}

fn cmd_hide(
    carrier: PathBuf,
    output: PathBuf,
    files: Vec<PathBuf>,
    messages: Vec<String>,
    mode_str: &str,
    password: Option<String>,
) -> Result<()> {
    let mode = match mode_str {
        "append" => EmbedMode::Append,
        "lsb" => EmbedMode::Lsb,
        other => bail!("modo desconocido: '{other}' (usa 'append' o 'lsb')"),
    };

    if files.is_empty() && messages.is_empty() {
        bail!("nada que esconder: pasa al menos --file o --message");
    }

    let mut items = Vec::new();
    for f in &files {
        let data = std::fs::read(f).with_context(|| format!("leyendo {}", f.display()))?;
        let name = f
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_else(|| "archivo".to_string());
        items.push(Item::File { name, data });
    }
    for m in &messages {
        let (subject, text) = m
            .split_once(':')
            .with_context(|| format!("mensaje '{m}' no tiene el formato 'asunto:texto'"))?;
        items.push(Item::Message {
            subject: subject.to_string(),
            text: text.to_string(),
        });
    }

    let password = match password {
        Some(p) => p,
        None => prompt_password_with_confirmation()?,
    };

    oursecret_core::hide(&carrier, &items, &password, mode, &output)?;
    println!(
        "Listo: {} elemento(s) escondido(s) en {}",
        items.len(),
        output.display()
    );
    Ok(())
}

fn cmd_extract(input: PathBuf, out_dir: PathBuf, password: Option<String>) -> Result<()> {
    let password = match password {
        Some(p) => p,
        None => rpassword::prompt_password("Contraseña: ")?,
    };

    let items = oursecret_core::read(&input, &password)?;
    std::fs::create_dir_all(&out_dir)?;

    for item in items {
        match item {
            Item::File { name, data } => {
                let path = oursecret_core::save_extracted_file(&out_dir, &name, &data)?;
                println!(
                    "archivo  -> {}",
                    for_terminal(&path.display().to_string(), false)
                );
            }
            Item::Message { subject, text } => {
                println!("mensaje  -> asunto: {}", for_terminal(&subject, false));
                println!("            {}", for_terminal(&text, true));
            }
        }
    }
    Ok(())
}

/// Escapa los caracteres de control de un texto extraído antes de imprimirlo.
///
/// Lo extraído lo eligió quien creó el archivo, y la terminal no solo pinta
/// texto: ejecuta las secuencias que empiezan por ESC (cambiar el título,
/// borrar la pantalla, escribir en el portapapeles con OSC 52...). Es el mismo
/// problema que `innerHTML` en la GUI, con otro intérprete al otro lado.
/// `keep_newlines` deja pasar `\n` y `\t` en el cuerpo de los mensajes.
///
/// ponytail: solo categoría Cc (C0, DEL, C1). Los caracteres bidi (U+202E...)
/// pueden disfrazar un nombre pero no ejecutan nada; escaparlos si hace falta.
fn for_terminal(s: &str, keep_newlines: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        if c.is_control() && !(keep_newlines && (c == '\n' || c == '\t')) {
            out.extend(c.escape_default());
        } else {
            out.push(c);
        }
    }
    out
}

fn cmd_capacity(carrier: PathBuf) -> Result<()> {
    let cap = oursecret_core::lsb_capacity(&carrier)
        .with_context(|| format!("abriendo {}", carrier.display()))?;
    println!("Capacidad en modo LSB: {cap} bytes para un archivo que no comprime (fotos, zips, vídeos); con varios, ~170 bytes menos por cada uno extra");
    Ok(())
}

fn prompt_password_with_confirmation() -> Result<String> {
    let p1 = rpassword::prompt_password("Contraseña: ")?;
    let p2 = rpassword::prompt_password("Repite la contraseña: ")?;
    if p1 != p2 {
        bail!("las contraseñas no coinciden");
    }
    Ok(p1)
}

#[cfg(test)]
mod tests {
    use super::for_terminal;

    #[test]
    fn for_terminal_neutralizes_escape_sequences() {
        // Título (OSC 0), borrar pantalla (CSI 2J), portapapeles (OSC 52),
        // CSI de 8 bits (C1 0x9B) y retorno de carro que pisa la línea.
        let evil = "\x1b]0;PWNED\x07\x1b[2J\x1b]52;c;ZXZpbA==\x07\u{9b}31m\rfalso";
        for keep in [false, true] {
            let out = for_terminal(evil, keep);
            assert!(!out.chars().any(char::is_control), "{out:?}");
            assert!(out.contains("PWNED") && out.contains("falso"));
        }
        // El texto normal (acentos incluidos) no cambia.
        assert_eq!(for_terminal("año, café", false), "año, café");
        // En el cuerpo se conservan los saltos de línea; en asunto/nombre, no.
        assert_eq!(for_terminal("a\nb\tc", true), "a\nb\tc");
        assert_eq!(for_terminal("a\nb", false), "a\\nb");
    }
}
