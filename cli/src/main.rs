//! CLI del port Linux de OurSecret.
//!
//! Replica, en línea de comandos, el flujo de 3 pasos del programa
//! original (elegir portador → añadir archivos/mensaje → contraseña) sin
//! usar ninguno de sus algoritmos propietarios — ver `oursecret-core` y
//! `docs/02_ARQUITECTURA.md` del proyecto para el diseño completo.

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
                println!("archivo  -> {}", path.display());
            }
            Item::Message { subject, text } => {
                println!("mensaje  -> asunto: {subject}");
                println!("            {text}");
            }
        }
    }
    Ok(())
}

fn cmd_capacity(carrier: PathBuf) -> Result<()> {
    let img = image::open(&carrier).with_context(|| format!("abriendo {}", carrier.display()))?;
    let cap = oursecret_core::embed::lsb::capacity_bytes(&img);
    println!("Capacidad en modo LSB: ~{cap} bytes (antes de cifrar/comprimir)");
    Ok(())
}

fn prompt_password_with_confirmation() -> Result<String> {
    let p1 = rpassword::prompt_password("Contraseña: ")?;
    let p2 = rpassword::prompt_password("Repite la contraseña: ")?;
    if p1 != p2 {
        bail!("las contraseñas no coinciden");
    }
    if p1.is_empty() {
        bail!("la contraseña no puede estar vacía");
    }
    Ok(p1)
}
