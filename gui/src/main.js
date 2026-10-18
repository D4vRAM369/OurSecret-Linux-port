// Sin bundler (frontendDist: "../src"): un `import "@tauri-apps/api"` no
// resolvería y abortaría todo el módulo. Se usa el global que inyecta
// `withGlobalTauri: true` en tauri.conf.json.
const invoke = window.__TAURI__.core.invoke;
const { open, save } = window.__TAURI__.dialog;

// ---------- Tabs ----------
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => b.classList.remove("active"));
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    btn.classList.add("active");
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

// ---------- Estado del flujo "Esconder" ----------
let carrierPath = null;
let items = []; // [{kind:'file', path, label} | {kind:'message', subject, text}]

const carrierNameEl = document.getElementById("carrier-name");
const carrierInfoEl = document.getElementById("carrier-info");
const itemListEl = document.getElementById("item-list");

document.getElementById("pick-carrier").addEventListener("click", async () => {
  const picked = await open({ multiple: false, title: "Elige el archivo portador" });
  if (!picked) return;
  carrierPath = picked;
  carrierNameEl.textContent = basename(picked);

  const isImage = await invoke("is_image_carrier", { carrierPath });
  // LSB solo funciona con PNG/BMP: si no lo es, se desactiva de verdad
  // (no basta con decirlo en el texto) y se vuelve a "crece".
  const lsbRadio = document.querySelector('input[name="mode"][value="lsb"]');
  lsbRadio.disabled = !isImage;
  if (!isImage && lsbRadio.checked) {
    document.querySelector('input[name="mode"][value="append"]').checked = true;
  }
  if (isImage) {
    const cap = await invoke("lsb_capacity", { carrierPath });
    carrierInfoEl.textContent = `Es una imagen compatible con el modo LSB — caben ${cap} bytes para un archivo que no comprime (fotos, zips, vídeos); con varios, ~170 bytes menos por cada uno extra.`;
  } else {
    carrierInfoEl.textContent = "No es una imagen PNG/BMP — solo estará disponible el modo 'crece'.";
  }
});

document.getElementById("add-file").addEventListener("click", async () => {
  const picked = await open({ multiple: true, title: "Elige archivo(s) a esconder" });
  if (!picked) return;
  const paths = Array.isArray(picked) ? picked : [picked];
  for (const p of paths) {
    items.push({ kind: "file", path: p, label: basename(p) });
  }
  renderItems();
});

document.getElementById("add-message").addEventListener("click", () => {
  const subject = document.getElementById("msg-subject").value.trim();
  const text = document.getElementById("msg-text").value.trim();
  if (!subject || !text) {
    return showResult(hideResultEl, "Escribe un asunto y un texto para el mensaje.", false);
  }
  items.push({ kind: "message", subject, text });
  document.getElementById("msg-subject").value = "";
  document.getElementById("msg-text").value = "";
  renderItems();
});

function renderItems() {
  itemListEl.innerHTML = "";
  items.forEach((item, idx) => {
    const li = document.createElement("li");
    const label =
      item.kind === "file" ? `📄 ${item.label}` : `✉️ Mensaje: "${item.subject}"`;
    // textContent, nunca innerHTML: el nombre de un archivo del disco puede
    // contener "<img onerror=...>" y se ejecutaría como código.
    const span = document.createElement("span");
    span.textContent = label;
    li.appendChild(span);
    const removeBtn = document.createElement("button");
    removeBtn.textContent = "quitar";
    removeBtn.addEventListener("click", () => {
      items.splice(idx, 1);
      renderItems();
    });
    li.appendChild(removeBtn);
    itemListEl.appendChild(li);
  });
}

// ---------- Esconder ----------
const hideResultEl = document.getElementById("hide-result");

document.getElementById("do-hide").addEventListener("click", async () => {
  hideResultEl.className = "result";
  hideResultEl.textContent = "";

  if (!carrierPath) {
    return showResult(hideResultEl, "Elige primero un archivo portador.", false);
  }
  if (items.length === 0) {
    return showResult(hideResultEl, "Añade al menos un archivo o un mensaje.", false);
  }
  const password = document.getElementById("password").value;
  const password2 = document.getElementById("password2").value;
  if (!password) {
    return showResult(hideResultEl, "Escribe una contraseña.", false);
  }
  if (password !== password2) {
    return showResult(hideResultEl, "Las contraseñas no coinciden.", false);
  }
  const mode = document.querySelector('input[name="mode"]:checked').value;

  const outputPath = await save({
    title: "Guardar como…",
    defaultPath: suggestOutputName(carrierPath, mode),
  });
  if (!outputPath) return;

  const payload = items.map((it) =>
    it.kind === "file"
      ? { kind: "file", path: it.path }
      : { kind: "message", subject: it.subject, text: it.text }
  );

  try {
    await invoke("hide_items", {
      carrierPath,
      outputPath,
      items: payload,
      password,
      mode,
    });
    showResult(hideResultEl, `Listo. Guardado en:\n${outputPath}`, true);
  } catch (err) {
    showResult(hideResultEl, `Error: ${err}`, false);
  }
});

// ---------- Extraer ----------
let stegoPath = null;
const stegoNameEl = document.getElementById("stego-name");
const extractResultEl = document.getElementById("extract-result");

document.getElementById("pick-stego").addEventListener("click", async () => {
  const picked = await open({ multiple: false, title: "Elige el archivo con datos ocultos" });
  if (!picked) return;
  stegoPath = picked;
  stegoNameEl.textContent = basename(picked);
});

document.getElementById("do-extract").addEventListener("click", async () => {
  extractResultEl.innerHTML = "";
  if (!stegoPath) {
    return showResult(extractResultEl, "Elige primero un archivo.", false);
  }
  const password = document.getElementById("extract-password").value;
  if (!password) {
    return showResult(extractResultEl, "Escribe la contraseña.", false);
  }

  const outDir = await open({ directory: true, title: "Carpeta donde guardar los archivos extraídos" });
  if (!outDir) return;

  try {
    const results = await invoke("extract_items", {
      inputPath: stegoPath,
      outDir,
      password,
    });
    extractResultEl.className = "result ok";
    results.forEach((item) => {
      const div = document.createElement("div");
      div.className = "extracted-item";
      // Todo lo extraído lo eligió quien creó el archivo (y conoce la
      // contraseña): es texto no confiable. Con innerHTML, un asunto como
      // "<img src=x onerror=...>" ejecutaría JS con acceso a window.__TAURI__.
      if (item.kind === "file") {
        div.append(textDiv("k", "archivo"), textDiv("", item.name), textDiv("hint", item.saved_to));
      } else {
        const subject = document.createElement("b");
        subject.textContent = item.subject;
        const subjectDiv = textDiv("", "");
        subjectDiv.appendChild(subject);
        div.append(textDiv("k", "mensaje"), subjectDiv, textDiv("", item.text));
      }
      extractResultEl.appendChild(div);
    });
  } catch (err) {
    showResult(extractResultEl, `Error: ${err}`, false);
  }
});

// ---------- Utilidades ----------
function textDiv(className, text) {
  const d = document.createElement("div");
  if (className) d.className = className;
  d.textContent = text;
  return d;
}

function basename(path) {
  return path.split(/[\\/]/).pop();
}

function suggestOutputName(carrier, mode) {
  const parts = carrier.split(/[\\/]/);
  const name = parts.pop();
  const dot = name.lastIndexOf(".");
  const base = dot > 0 ? name.slice(0, dot) : name;
  const ext = mode === "lsb" ? "png" : dot > 0 ? name.slice(dot + 1) : "bin";
  return `${base}_secreto.${ext}`;
}

function showResult(el, message, ok) {
  el.className = `result ${ok ? "ok" : "err"}`;
  el.textContent = message;
}
