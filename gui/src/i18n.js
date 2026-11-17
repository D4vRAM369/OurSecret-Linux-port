// Diccionario de internacionalización (ES / EN) para OurSecret Linux.
// Si el idioma del sistema no empieza por "es", arranca en inglés por defecto.

export const STRINGS = {
  es: {
    page_title: "OurSecret Linux",
    tab_hide: "Esconder",
    tab_extract: "Extraer",
    lang_switch_title: "Cambiar idioma (Español / English)",
    step_carrier: "1. Archivo portador",
    carrier_none: "Ninguno seleccionado",
    carrier_hint_default:
      "Cualquier archivo sirve (PNG/BMP permite además modo LSB). Arrastra aquí o elige uno.",
    btn_pick: "Elegir…",
    step_mode: "2. Modo de ocultación",
    mode_append_title: "Crece",
    mode_append_desc: "Cualquier archivo. Los datos van al final y el archivo pesa más.",
    mode_append_warn: "En PNG, JPEG, PDF o ZIP se nota que sobran datos.",
    mode_lsb_title: "Mismas dimensiones",
    mode_lsb_desc: "Solo PNG/BMP. Repartido por toda la imagen: más discreto.",
    mode_lsb_warn: "Cabe poco, y la salida siempre es PNG.",
    step_password: "3. Contraseña",
    pw_placeholder: "Contraseña",
    pw2_placeholder: "Repite la contraseña",
    pw_show_hide: "Mostrar u ocultar contraseña",
    pw2_show_hide: "Mostrar u ocultar confirmación",
    pw_toggle_title: "Mostrar/ocultar",
    step_items: "Qué quieres esconder",
    items_drop_hint: "Arrastra archivos aquí o añádelos:",
    btn_add_file: "+ Añadir archivo",
    items_empty: "Todavía no has añadido nada.",
    msg_details_summary: "Añadir un mensaje de texto",
    msg_subject_ph: "Asunto",
    msg_text_ph: "Escribe el mensaje…",
    btn_add_msg: "Añadir mensaje a la lista",
    summary_empty: "Elige un portador y añade al menos un archivo o mensaje.",
    btn_do_hide: "Esconder y guardar como…",
    extract_step_file: "1. Archivo con datos ocultos",
    extract_drop_hint: "Arrastra aquí el archivo o pulsa Elegir…",
    extract_step_pw: "2. Contraseña",
    btn_do_extract: "Extraer en carpeta…",
    footer_text:
      "Reimplementación clean-room, sin código del OurSecret original. Formato propio: AES-256-GCM + Argon2id.",
    thumb_default: "ARCH",
    analyzing: "Analizando…",
    carrier_lsb_ok: (sizeLabel, cap) =>
      `${sizeLabel}PNG/BMP: admite ambos modos. En LSB caben ~${cap}.`,
    carrier_append_only: (sizeLabel) =>
      `${sizeLabel}No es PNG/BMP: solo disponible el modo crece (append).`,
    carrier_probe_err: (err) => `No se pudo analizar el portador: ${err}`,
    warn_dirs: (list) => `No se pueden añadir carpetas (${list}); selecciona archivos.`,
    warn_dups: (list) =>
      `Ya había archivo(s) con el mismo nombre (${list}); renómbralo antes de añadirlo.`,
    item_msg_label: (subject) => `✉️ Mensaje: "${subject}"`,
    btn_remove: "quitar",
    btn_remove_aria: (label) => `Quitar ${label}`,
    usage_over: (used, cap) =>
      `No cabe: ~${used} de ~${cap}. Quita algo o usa el modo crece.`,
    usage_ok: (used, cap, unknown) =>
      `~${used} de ~${cap}${unknown ? " (sin contar algún archivo ilegible)" : ""}`,
    summary_text: (count, est, mode, outHint) =>
      `${count} elemento(s) (${est}) · Modo ${mode}${outHint}`,
    summary_out: (name) => ` · Salida: ${name}`,
    pw_repeat_hint: "Repite la contraseña para confirmar.",
    pw_match_ok: "✓ Las contraseñas coinciden",
    pw_match_short: "✓ Las contraseñas coinciden (aviso: es corta, usa al menos 10 caracteres)",
    pw_match_err: "Las contraseñas no coinciden",
    err_no_carrier: "Elige primero un archivo portador.",
    err_no_items: "Añade al menos un archivo o un mensaje.",
    err_no_pw: "Escribe una contraseña.",
    err_pw_mismatch: "Las contraseñas no coinciden.",
    err_msg_empty: "Escribe un asunto y un texto para el mensaje.",
    dialog_pick_carrier: "Elige el archivo portador",
    dialog_pick_files: "Elige archivo(s) a esconder",
    dialog_save_as: "Guardar como…",
    dialog_pick_stego: "Elige el archivo con datos ocultos",
    dialog_pick_outdir: "Carpeta donde guardar los archivos extraídos",
    busy_msg: "Trabajando… (derivar la clave de la contraseña tarda unos segundos)",
    hide_ok: (path) => `Listo. Guardado en:\n${path}`,
    err_prefix: (err) => `Error: ${err}`,
    extract_err_no_file: "Elige primero un archivo.",
    extract_ok_count: (n) => `Extraído(s) ${n} elemento(s):`,
    kind_file: "archivo",
    kind_message: "mensaje",
    copy_path: "Copiar ruta",
    copy_text: "Copiar texto",
    copied: "¡Copiado!",
    copy_unavailable: "No disponible",
    default_out_suffix: "_secreto",
    locale: "es",
  },
  en: {
    page_title: "OurSecret Linux",
    tab_hide: "Hide",
    tab_extract: "Extract",
    lang_switch_title: "Switch language (Español / English)",
    step_carrier: "1. Carrier file",
    carrier_none: "None selected",
    carrier_hint_default:
      "Any file works (PNG/BMP also supports LSB mode). Drag and drop here or choose one.",
    btn_pick: "Choose…",
    step_mode: "2. Hiding mode",
    mode_append_title: "Grow",
    mode_append_desc: "Any file. Data is appended at the end and the file grows.",
    mode_append_warn: "In PNG, JPEG, PDF or ZIP trailing data can be spotted.",
    mode_lsb_title: "Same dimensions",
    mode_lsb_desc: "PNG/BMP only. Spread across pixels: much more discreet.",
    mode_lsb_warn: "Lower capacity, and output is always PNG.",
    step_password: "3. Password",
    pw_placeholder: "Password",
    pw2_placeholder: "Repeat password",
    pw_show_hide: "Show or hide password",
    pw2_show_hide: "Show or hide confirmation",
    pw_toggle_title: "Show/hide",
    step_items: "What to hide",
    items_drop_hint: "Drag files here or add them:",
    btn_add_file: "+ Add file",
    items_empty: "Nothing added yet.",
    msg_details_summary: "Add a text message",
    msg_subject_ph: "Subject",
    msg_text_ph: "Write your message…",
    btn_add_msg: "Add message to list",
    summary_empty: "Choose a carrier file and add at least one file or message.",
    btn_do_hide: "Hide and save as…",
    extract_step_file: "1. File with hidden data",
    extract_drop_hint: "Drag the file here or click Choose…",
    extract_step_pw: "2. Password",
    btn_do_extract: "Extract to folder…",
    footer_text:
      "Clean-room reimplementation, no code from the original OurSecret. Own format: AES-256-GCM + Argon2id.",
    thumb_default: "FILE",
    analyzing: "Analyzing…",
    carrier_lsb_ok: (sizeLabel, cap) =>
      `${sizeLabel}PNG/BMP: both modes supported. LSB fits ~${cap}.`,
    carrier_append_only: (sizeLabel) =>
      `${sizeLabel}Not PNG/BMP: only grow (append) mode is available.`,
    carrier_probe_err: (err) => `Could not inspect carrier: ${err}`,
    warn_dirs: (list) => `Folders cannot be added (${list}); select individual files.`,
    warn_dups: (list) =>
      `File(s) with the same name already in list (${list}); rename before adding.`,
    item_msg_label: (subject) => `✉️ Message: "${subject}"`,
    btn_remove: "remove",
    btn_remove_aria: (label) => `Remove ${label}`,
    usage_over: (used, cap) =>
      `Too large: ~${used} of ~${cap}. Remove items or use grow (append) mode.`,
    usage_ok: (used, cap, unknown) =>
      `~${used} of ~${cap}${unknown ? " (excluding unreadable file)" : ""}`,
    summary_text: (count, est, mode, outHint) =>
      `${count} item(s) (${est}) · ${mode} mode${outHint}`,
    summary_out: (name) => ` · Output: ${name}`,
    pw_repeat_hint: "Repeat the password to confirm.",
    pw_match_ok: "✓ Passwords match",
    pw_match_short: "✓ Passwords match (warning: short password, use at least 10 characters)",
    pw_match_err: "Passwords do not match",
    err_no_carrier: "Choose a carrier file first.",
    err_no_items: "Add at least one file or message.",
    err_no_pw: "Enter a password.",
    err_pw_mismatch: "Passwords do not match.",
    err_msg_empty: "Enter both a subject and a message text.",
    dialog_pick_carrier: "Choose carrier file",
    dialog_pick_files: "Choose file(s) to hide",
    dialog_save_as: "Save as…",
    dialog_pick_stego: "Choose file with hidden data",
    dialog_pick_outdir: "Folder to save extracted files",
    busy_msg: "Working… (key derivation takes a few seconds)",
    hide_ok: (path) => `Done. Saved to:\n${path}`,
    err_prefix: (err) => `Error: ${err}`,
    extract_err_no_file: "Choose a file first.",
    extract_ok_count: (n) => `Extracted ${n} item(s):`,
    kind_file: "file",
    kind_message: "message",
    copy_path: "Copy path",
    copy_text: "Copy text",
    copied: "Copied!",
    copy_unavailable: "Unavailable",
    default_out_suffix: "_secret",
    locale: "en",
  },
};

const STORAGE_KEY = "oursecret-lang";

export function detectInitialLang() {
  try {
    const saved = localStorage.getItem(STORAGE_KEY);
    if (saved === "es" || saved === "en") return saved;
  } catch {
    // localStorage puede no estar disponible en contextos restringidos
  }
  const nav = (navigator.language || navigator.languages?.[0] || "en").toLowerCase();
  return nav.startsWith("es") ? "es" : "en";
}

export function saveLang(lang) {
  try {
    localStorage.setItem(STORAGE_KEY, lang);
  } catch {
    // ignorar si falla almacenamiento
  }
}
