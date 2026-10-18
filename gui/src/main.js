// Sin bundler (frontendDist: "../src"): un `import "@tauri-apps/api"` no
// resolvería y abortaría todo el módulo. Se usa el global que inyecta
// `withGlobalTauri: true` en tauri.conf.json.
const invoke = window.__TAURI__.core.invoke;
const { open, save } = window.__TAURI__.dialog;

// ---------- Tabs ----------
document.querySelectorAll(".tab-btn").forEach((btn) => {
  btn.addEventListener("click", () => {
    document.querySelectorAll(".tab-btn").forEach((b) => {
      b.classList.toggle("active", b === btn);
      b.setAttribute("aria-selected", String(b === btn));
    });
    document.querySelectorAll(".tab-panel").forEach((p) => p.classList.remove("active"));
    document.getElementById(`tab-${btn.dataset.tab}`).classList.add("active");
  });
});

// ---------- Estado del flujo "Esconder" ----------
let carrierPath = null;
let carrierCapacity = null; // bytes en modo LSB; null si el portador no es imagen
let items = []; // [{kind:'file', path, label, size} | {kind:'message', subject, text}]

const carrierNameEl = document.getElementById("carrier-name");
const carrierInfoEl = document.getElementById("carrier-info");
const itemListEl = document.getElementById("item-list");
const hideResultEl = document.getElementById("hide-result");
const hideBtn = document.getElementById("do-hide");
const lsbRadio = document.querySelector('input[name="mode"][value="lsb"]');
const appendRadio = document.querySelector('input[name="mode"][value="append"]');

document.getElementById("pick-carrier").addEventListener("click", async () => {
  const picked = await open({ multiple: false, title: "Elige el archivo portador" });
  if (!picked) return;
  carrierPath = picked;
  carrierNameEl.textContent = basename(picked);
  // Se vacía ANTES de preguntar: si algo falla a mitad, no puede quedar a la
  // vista la información del portador anterior junto al nombre del nuevo.
  carrierInfoEl.textContent = "Analizando…";
  carrierCapacity = null;

  try {
    const isImage = await invoke("is_lsb_carrier", { carrierPath });
    // LSB solo funciona con PNG/BMP: si no lo es, se desactiva de verdad
    // (no basta con decirlo en el texto) y se vuelve a "crece".
    lsbRadio.disabled = !isImage;
    if (!isImage && lsbRadio.checked) appendRadio.checked = true;
    if (isImage) {
      carrierCapacity = await invoke("lsb_capacity", { carrierPath });
      carrierInfoEl.textContent = `Imagen PNG/BMP: admite los dos modos. En mismas dimensiones (LSB) caben ~${formatBytes(carrierCapacity)}.`;
    } else {
      carrierInfoEl.textContent = "No es una imagen PNG/BMP: solo está disponible el modo crece (append).";
    }
  } catch (err) {
    carrierInfoEl.textContent = `No se pudo analizar el portador: ${err}`;
  }
  updateUsage();
});

document.querySelectorAll('input[name="mode"]').forEach((r) => r.addEventListener("change", updateUsage));

document.getElementById("add-file").addEventListener("click", async () => {
  const picked = await open({ multiple: true, title: "Elige archivo(s) a esconder" });
  if (!picked) return;
  const paths = Array.isArray(picked) ? picked : [picked];
  for (const p of paths) {
    // Sin tamaño (null) el archivo se esconde igual; solo falta en la barra.
    const size = await invoke("file_size", { path: p }).catch(() => null);
    items.push({ kind: "file", path: p, label: basename(p), size });
  }
  renderItems();
});

document.getElementById("add-message").addEventListener("click", () => {
  const subject = document.getElementById("msg-subject").value.trim();
  // El texto se guarda tal cual: trim() solo para saber si está vacío. Si no,
  // la sangría y los saltos del principio/final se perderían al esconderlo.
  const text = document.getElementById("msg-text").value;
  if (!subject || !text.trim()) {
    return showResult(hideResultEl, "Escribe un asunto y un texto para el mensaje.", false);
  }
  items.push({ kind: "message", subject, text });
  document.getElementById("msg-subject").value = "";
  document.getElementById("msg-text").value = "";
  renderItems();
});

function renderItems() {
  itemListEl.replaceChildren();
  if (items.length === 0) {
    const li = document.createElement("li");
    li.className = "empty";
    li.textContent = "Todavía no has añadido nada.";
    itemListEl.appendChild(li);
  }
  items.forEach((item, idx) => {
    const li = document.createElement("li");
    const label =
      item.kind === "file"
        ? `📄 ${item.label}${item.size != null ? ` · ${formatBytes(item.size)}` : ""}`
        : `✉️ Mensaje: "${item.subject}"`;
    // textContent, nunca innerHTML: el nombre de un archivo del disco puede
    // contener "<img onerror=...>" y se ejecutaría como código.
    const span = document.createElement("span");
    span.textContent = label;
    li.appendChild(span);
    const removeBtn = document.createElement("button");
    removeBtn.textContent = "quitar";
    removeBtn.setAttribute("aria-label", `Quitar ${label}`);
    removeBtn.addEventListener("click", () => {
      items.splice(idx, 1);
      renderItems();
    });
    li.appendChild(removeBtn);
    itemListEl.appendChild(li);
  });
  updateUsage();
}

// Barra "usado / capacidad", solo en modo LSB, que es el que tiene tope.
// Estimación pesimista: tamaños sin comprimir; `lsb_capacity` ya descuenta
// el sobrecoste del primer item y cada uno extra suma ~170 bytes (core).
const usageEl = document.getElementById("usage");
const usageFillEl = document.getElementById("usage-fill");
const usageTextEl = document.getElementById("usage-text");
const enc = new TextEncoder();

function updateUsage() {
  const show = carrierCapacity != null && lsbRadio.checked && items.length > 0;
  usageEl.hidden = !show;
  if (!show) return;
  const unknown = items.some((it) => it.kind === "file" && it.size == null);
  const used =
    items.reduce(
      (sum, it) =>
        sum + (it.kind === "file" ? it.size ?? 0 : enc.encode(`${it.subject}\n${it.text}`).length),
      0
    ) +
    170 * (items.length - 1);
  const over = used > carrierCapacity;
  usageEl.classList.toggle("over", over);
  usageFillEl.style.width = `${Math.min(100, (used / carrierCapacity) * 100)}%`;
  usageTextEl.textContent = over
    ? `No cabe: ~${formatBytes(used)} de ~${formatBytes(carrierCapacity)}. Quita algo o usa el modo crece.`
    : `~${formatBytes(used)} de ~${formatBytes(carrierCapacity)}${unknown ? " (sin contar algún archivo ilegible)" : ""}`;
}

// ---------- Esconder ----------
hideBtn.addEventListener("click", async () => {
  hideResultEl.className = "result";
  hideResultEl.textContent = "";

  if (!carrierPath) {
    return showResult(hideResultEl, "Elige primero un archivo portador.", false);
  }
  if (items.length === 0) {
    return showResult(hideResultEl, "Añade al menos un archivo o un mensaje.", false);
  }
  const pw1 = document.getElementById("password");
  const pw2 = document.getElementById("password2");
  if (!pw1.value) {
    return showResult(hideResultEl, "Escribe una contraseña.", false);
  }
  if (pw1.value !== pw2.value) {
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

  await whileBusy(hideBtn, hideResultEl, async () => {
    try {
      await invoke("hide_items", {
        carrierPath,
        outputPath,
        items: payload,
        password: pw1.value,
        mode,
      });
      pw1.value = pw2.value = ""; // que no quede a la vista de quien venga después
      showResult(hideResultEl, `Listo. Guardado en:\n${outputPath}`, true);
    } catch (err) {
      showResult(hideResultEl, `Error: ${err}`, false);
    }
  });
});

// ---------- Extraer ----------
let stegoPath = null;
const stegoNameEl = document.getElementById("stego-name");
const extractResultEl = document.getElementById("extract-result");
const extractBtn = document.getElementById("do-extract");

document.getElementById("pick-stego").addEventListener("click", async () => {
  const picked = await open({ multiple: false, title: "Elige el archivo con datos ocultos" });
  if (!picked) return;
  stegoPath = picked;
  stegoNameEl.textContent = basename(picked);
});

extractBtn.addEventListener("click", async () => {
  extractResultEl.replaceChildren();
  if (!stegoPath) {
    return showResult(extractResultEl, "Elige primero un archivo.", false);
  }
  const pwEl = document.getElementById("extract-password");
  if (!pwEl.value) {
    return showResult(extractResultEl, "Escribe la contraseña.", false);
  }

  const outDir = await open({ directory: true, title: "Carpeta donde guardar los archivos extraídos" });
  if (!outDir) return;

  await whileBusy(extractBtn, extractResultEl, async () => {
    try {
      const results = await invoke("extract_items", {
        inputPath: stegoPath,
        outDir,
        password: pwEl.value,
      });
      pwEl.value = "";
      // El verde es para la línea de estado, no para el contenido extraído.
      extractResultEl.className = "result";
      extractResultEl.replaceChildren(textDiv("status-ok", `Extraído(s) ${results.length} elemento(s):`));
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
});

// Enter en un campo de contraseña = pulsar su botón.
document.getElementById("password2").addEventListener("keydown", (e) => {
  if (e.key === "Enter") hideBtn.click();
});
document.getElementById("extract-password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") extractBtn.click();
});

// ---------- Utilidades ----------

// Mientras el backend trabaja (Argon2 tarda): botón desactivado, para que
// un segundo clic no lance la operación otra vez, y un aviso de que algo
// está pasando, para que nadie piense que el primero no funcionó.
async function whileBusy(btn, resultEl, work) {
  btn.disabled = true;
  resultEl.className = "result";
  resultEl.textContent = "Trabajando… (derivar la clave de la contraseña tarda unos segundos)";
  try {
    await work();
  } finally {
    btn.disabled = false;
  }
}

function textDiv(className, text) {
  const d = document.createElement("div");
  if (className) d.className = className;
  d.textContent = text;
  return d;
}

function formatBytes(n) {
  const fmt = (x) => x.toLocaleString("es", { maximumFractionDigits: 1 });
  if (n < 1024) return `${n} bytes`;
  if (n < 1024 * 1024) return `${fmt(n / 1024)} KB`;
  return `${fmt(n / (1024 * 1024))} MB`;
}

function basename(path) {
  return path.split(/[\\/]/).pop();
}

function suggestOutputName(carrier, mode) {
  const name = basename(carrier);
  const dot = name.lastIndexOf(".");
  const base = dot > 0 ? name.slice(0, dot) : name;
  const ext = mode === "lsb" ? "png" : dot > 0 ? name.slice(dot + 1) : "bin";
  return `${base}_secreto.${ext}`;
}

function showResult(el, message, ok) {
  el.className = `result ${ok ? "ok" : "err"}`;
  el.textContent = message;
}

renderItems();
