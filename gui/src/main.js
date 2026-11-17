import { STRINGS, detectInitialLang, saveLang } from "./i18n.js";

// Sin bundler (frontendDist: "../src"): un `import "@tauri-apps/api"` no
// resolvería y abortaría todo el módulo. Se usa el global que inyecta
// `withGlobalTauri: true` en tauri.conf.json.
const invoke = window.__TAURI__.core.invoke;
const { open, save } = window.__TAURI__.dialog;

let currentLang = detectInitialLang();
const t = () => STRINGS[currentLang];

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

// ---------- Mostrar / ocultar contraseña ----------
document.querySelectorAll("[data-eye]").forEach((eyeBtn) => {
  eyeBtn.addEventListener("click", () => {
    const input = document.getElementById(eyeBtn.dataset.eye);
    if (!input) return;
    const show = input.type === "password";
    input.type = show ? "text" : "password";
    eyeBtn.setAttribute("aria-pressed", String(show));
  });
});

// ---------- Estado del flujo "Esconder" ----------
let carrierPath = null;
let carrierSize = null;
let carrierCapacity = null; // bytes en modo LSB; null si el portador no es imagen
let items = []; // [{kind:'file', path, label, size} | {kind:'message', subject, text}]

const carrierNameEl = document.getElementById("carrier-name");
const carrierInfoEl = document.getElementById("carrier-info");
const carrierThumbEl = document.getElementById("carrier-thumb");
const itemListEl = document.getElementById("item-list");
const hideResultEl = document.getElementById("hide-result");
const hideSummaryEl = document.getElementById("hide-summary");
const hideBtn = document.getElementById("do-hide");
const lsbRadio = document.querySelector('input[name="mode"][value="lsb"]');
const appendRadio = document.querySelector('input[name="mode"][value="append"]');
const pw1El = document.getElementById("password");
const pw2El = document.getElementById("password2");
const pwMatchEl = document.getElementById("pw-match");
const langSwitchBtn = document.getElementById("lang-switch");

function renderCarrierInfo() {
  if (!carrierPath) {
    carrierNameEl.textContent = t().carrier_none;
    carrierThumbEl.textContent = t().thumb_default;
    carrierInfoEl.textContent = t().carrier_hint_default;
    return;
  }
  const sizeLabel = carrierSize != null ? `${formatBytes(carrierSize)} · ` : "";
  if (carrierCapacity !== null) {
    carrierInfoEl.textContent = t().carrier_lsb_ok(sizeLabel, formatBytes(carrierCapacity));
  } else {
    carrierInfoEl.textContent = t().carrier_append_only(sizeLabel);
  }
}

async function selectCarrier(picked) {
  carrierPath = picked;
  const name = basename(picked);
  carrierNameEl.textContent = name;
  carrierThumbEl.textContent = extBadge(name);
  carrierThumbEl.classList.remove("is-image");
  // Se vacía ANTES de preguntar: si algo falla a mitad, no puede quedar a la
  // vista la información del portador anterior junto al nombre del nuevo.
  carrierInfoEl.textContent = t().analyzing;
  carrierCapacity = null;
  carrierSize = null;

  try {
    const [cap, size] = await Promise.all([
      invoke("probe_lsb_carrier", { carrierPath }),
      invoke("file_size", { path: carrierPath }).catch(() => null),
    ]);
    carrierSize = size;
    const isImage = cap !== null;
    // LSB solo funciona con PNG/BMP: si no lo es, se desactiva de verdad
    // (no basta con decirlo en el texto) y se vuelve a "crece".
    lsbRadio.disabled = !isImage;
    if (!isImage && lsbRadio.checked) {
      appendRadio.checked = true;
    } else if (isImage && (items.length === 0 || estimatedPayloadBytes() <= cap)) {
      // Si el portador es PNG/BMP y el contenido cabe, preseleccionamos LSB por ser más discreto.
      lsbRadio.checked = true;
    }
    if (isImage) {
      carrierCapacity = cap;
      carrierThumbEl.classList.add("is-image");
    }
    renderCarrierInfo();
  } catch (err) {
    carrierInfoEl.textContent = t().carrier_probe_err(err);
  }
  updateUsage();
  updateSummary();
}

async function addFiles(paths) {
  const skipped = [];
  const dirs = [];
  for (const p of paths) {
    const label = basename(p);
    const dup = items.some((it) => it.kind === "file" && it.label === label);
    if (dup) {
      skipped.push(label);
      continue;
    }
    let size = null;
    try {
      size = await invoke("file_size", { path: p });
    } catch (err) {
      if (String(err).includes("carpeta")) {
        dirs.push(label);
        continue;
      }
      // Sin tamaño (null) el archivo se esconde igual; solo falta en la barra.
    }
    items.push({ kind: "file", path: p, label, size });
  }
  renderItems();
  const warnings = [];
  if (dirs.length > 0) {
    warnings.push(t().warn_dirs(dirs.join(", ")));
  }
  if (skipped.length > 0) {
    warnings.push(t().warn_dups(skipped.join(", ")));
  }
  if (warnings.length > 0) {
    showResult(hideResultEl, warnings.join(" "), false);
  }
}

document.getElementById("pick-carrier").addEventListener("click", async () => {
  const picked = await open({ multiple: false, title: t().dialog_pick_carrier });
  if (picked) await selectCarrier(picked);
});

document.querySelectorAll('input[name="mode"]').forEach((r) =>
  r.addEventListener("change", () => {
    updateUsage();
    updateSummary();
  })
);

document.getElementById("add-file").addEventListener("click", async () => {
  const picked = await open({ multiple: true, title: t().dialog_pick_files });
  if (!picked) return;
  await addFiles(Array.isArray(picked) ? picked : [picked]);
});

document.getElementById("add-message").addEventListener("click", () => {
  const subject = document.getElementById("msg-subject").value.trim();
  // El texto se guarda tal cual: trim() solo para saber si está vacío. Si no,
  // la sangría y los saltos del principio/final se perderían al esconderlo.
  const text = document.getElementById("msg-text").value;
  if (!subject || !text.trim()) {
    return showResult(hideResultEl, t().err_msg_empty, false);
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
    li.textContent = t().items_empty;
    itemListEl.appendChild(li);
  }
  items.forEach((item, idx) => {
    const li = document.createElement("li");
    const label =
      item.kind === "file"
        ? `📄 ${item.label}${item.size != null ? ` · ${formatBytes(item.size)}` : ""}`
        : t().item_msg_label(item.subject);
    // textContent, nunca innerHTML: el nombre de un archivo del disco puede
    // contener "<img onerror=...>" y se ejecutaría como código.
    const span = document.createElement("span");
    span.textContent = label;
    li.appendChild(span);
    const removeBtn = document.createElement("button");
    removeBtn.textContent = t().btn_remove;
    removeBtn.setAttribute("aria-label", t().btn_remove_aria(label));
    removeBtn.addEventListener("click", () => {
      items.splice(idx, 1);
      renderItems();
    });
    li.appendChild(removeBtn);
    itemListEl.appendChild(li);
  });
  updateUsage();
  updateSummary();
}

// Barra "usado / capacidad", solo en modo LSB, que es el que tiene tope.
// Estimación pesimista: tamaños sin comprimir; `lsb_capacity` ya descuenta
// el sobrecoste del primer item y cada uno extra suma ~170 bytes (core).
const usageEl = document.getElementById("usage");
const usageFillEl = document.getElementById("usage-fill");
const usageTextEl = document.getElementById("usage-text");
const enc = new TextEncoder();

function estimatedPayloadBytes() {
  if (items.length === 0) return 0;
  return (
    items.reduce(
      (sum, it) =>
        sum + (it.kind === "file" ? it.size ?? 0 : enc.encode(`${it.subject}\n${it.text}`).length),
      0
    ) +
    170 * (items.length - 1)
  );
}

function updateUsage() {
  const show = carrierCapacity != null && lsbRadio.checked && items.length > 0;
  usageEl.hidden = !show;
  if (!show) return;
  const unknown = items.some((it) => it.kind === "file" && it.size == null);
  const used = estimatedPayloadBytes();
  const over = used > carrierCapacity;
  usageEl.classList.toggle("over", over);
  usageFillEl.style.width = `${Math.min(100, (used / carrierCapacity) * 100)}%`;
  usageTextEl.textContent = over
    ? t().usage_over(formatBytes(used), formatBytes(carrierCapacity))
    : t().usage_ok(formatBytes(used), formatBytes(carrierCapacity), unknown);
}

function updateSummary() {
  if (!carrierPath && items.length === 0) {
    hideSummaryEl.textContent = t().summary_empty;
    return;
  }
  const mode = document.querySelector('input[name="mode"]:checked').value;
  const count = items.length;
  const est = count > 0 ? `~${formatBytes(estimatedPayloadBytes())}` : "0 B";
  const outHint = carrierPath ? t().summary_out(suggestOutputName(carrierPath, mode)) : "";
  hideSummaryEl.textContent = t().summary_text(count, est, mode.toUpperCase(), outHint);
}

function updatePasswordMatch() {
  const a = pw1El.value;
  const b = pw2El.value;
  if (!a && !b) {
    pwMatchEl.className = "pw-match";
    pwMatchEl.textContent = "";
    return;
  }
  if (!b) {
    pwMatchEl.className = "pw-match";
    pwMatchEl.textContent = t().pw_repeat_hint;
    return;
  }
  if (a === b) {
    pwMatchEl.className = "pw-match ok";
    pwMatchEl.textContent = a.length < 10 ? t().pw_match_short : t().pw_match_ok;
  } else {
    pwMatchEl.className = "pw-match err";
    pwMatchEl.textContent = t().pw_match_err;
  }
}

pw1El.addEventListener("input", updatePasswordMatch);
pw2El.addEventListener("input", updatePasswordMatch);

// ---------- Esconder ----------
hideBtn.addEventListener("click", async () => {
  hideResultEl.className = "result";
  hideResultEl.textContent = "";

  if (!carrierPath) {
    return showResult(hideResultEl, t().err_no_carrier, false);
  }
  if (items.length === 0) {
    return showResult(hideResultEl, t().err_no_items, false);
  }
  if (!pw1El.value) {
    return showResult(hideResultEl, t().err_no_pw, false);
  }
  if (pw1El.value !== pw2El.value) {
    return showResult(hideResultEl, t().err_pw_mismatch, false);
  }
  const mode = document.querySelector('input[name="mode"]:checked').value;

  const outputPath = await save({
    title: t().dialog_save_as,
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
        password: pw1El.value,
        mode,
      });
      pw1El.value = pw2El.value = ""; // que no quede a la vista de quien venga después
      updatePasswordMatch();
      showResult(hideResultEl, t().hide_ok(outputPath), true);
    } catch (err) {
      showResult(hideResultEl, t().err_prefix(err), false);
    }
  });
});

// ---------- Extraer ----------
let stegoPath = null;
const stegoNameEl = document.getElementById("stego-name");
const extractResultEl = document.getElementById("extract-result");
const extractBtn = document.getElementById("do-extract");

function selectStego(picked) {
  stegoPath = picked;
  stegoNameEl.textContent = basename(picked);
}

document.getElementById("pick-stego").addEventListener("click", async () => {
  const picked = await open({ multiple: false, title: t().dialog_pick_stego });
  if (picked) selectStego(picked);
});

extractBtn.addEventListener("click", async () => {
  extractResultEl.replaceChildren();
  if (!stegoPath) {
    return showResult(extractResultEl, t().extract_err_no_file, false);
  }
  const pwEl = document.getElementById("extract-password");
  if (!pwEl.value) {
    return showResult(extractResultEl, t().err_no_pw, false);
  }

  const outDir = await open({ directory: true, title: t().dialog_pick_outdir });
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
      extractResultEl.replaceChildren(textDiv("status-ok", t().extract_ok_count(results.length)));
      results.forEach((item) => {
        const div = document.createElement("div");
        div.className = "extracted-item";
        const body = document.createElement("div");
        body.className = "extracted-body";
        // Todo lo extraído lo eligió quien creó el archivo (y conoce la
        // contraseña): es texto no confiable. Con innerHTML, un asunto como
        // "<img src=x onerror=...>" ejecutaría JS con acceso a window.__TAURI__.
        if (item.kind === "file") {
          body.append(
            textDiv("k", t().kind_file),
            textDiv("", item.name),
            textDiv("hint", item.saved_to)
          );
          div.append(body, makeCopyButton("copy_path", item.saved_to));
        } else {
          const subject = document.createElement("b");
          subject.textContent = item.subject;
          const subjectDiv = textDiv("", "");
          subjectDiv.appendChild(subject);
          body.append(textDiv("k", t().kind_message), subjectDiv, textDiv("", item.text));
          div.append(body, makeCopyButton("copy_text", item.text));
        }
        extractResultEl.appendChild(div);
      });
    } catch (err) {
      showResult(extractResultEl, t().err_prefix(err), false);
    }
  });
});

// Enter en un campo de contraseña = pulsar su botón.
pw2El.addEventListener("keydown", (e) => {
  if (e.key === "Enter") hideBtn.click();
});
document.getElementById("extract-password").addEventListener("keydown", (e) => {
  if (e.key === "Enter") extractBtn.click();
});

// ---------- Drag & Drop nativo (Tauri 2) ----------
const carrierDropEl = document.getElementById("carrier-dropzone");
const itemsDropEl = document.getElementById("items-dropzone");
const stegoDropEl = document.getElementById("stego-dropzone");

function clearDropHighlights() {
  carrierDropEl.classList.remove("dragover");
  itemsDropEl.classList.remove("dragover");
  stegoDropEl.classList.remove("dragover");
}

function hitDropzone(position) {
  if (!position) return null;
  const x = position.x / (window.devicePixelRatio || 1);
  const y = position.y / (window.devicePixelRatio || 1);
  const extractActive = document.getElementById("tab-extract").classList.contains("active");
  if (extractActive) {
    return stegoDropEl;
  }
  const r = carrierDropEl.getBoundingClientRect();
  if (x >= r.left && x <= r.right && y >= r.top && y <= r.bottom) {
    return carrierDropEl;
  }
  return itemsDropEl;
}

if (window.__TAURI__?.webview?.getCurrentWebview) {
  window.__TAURI__.webview.getCurrentWebview().onDragDropEvent(async (event) => {
    const p = event.payload;
    if (p.type === "enter" || p.type === "over") {
      clearDropHighlights();
      const target = hitDropzone(p.position);
      if (target) target.classList.add("dragover");
    } else if (p.type === "leave") {
      clearDropHighlights();
    } else if (p.type === "drop") {
      clearDropHighlights();
      const paths = p.paths || [];
      if (paths.length === 0) return;
      const target = hitDropzone(p.position);
      if (target === stegoDropEl) {
        selectStego(paths[0]);
      } else if (target === carrierDropEl) {
        await selectCarrier(paths[0]);
      } else {
        await addFiles(paths);
      }
    }
  });
}

// ---------- Selector de idioma (i18n ES / EN) ----------
function applyLanguage(lang) {
  currentLang = lang;
  const s = t();
  document.documentElement.lang = lang;
  document.title = s.page_title;
  langSwitchBtn.textContent = lang === "es" ? "EN" : "ES";
  langSwitchBtn.setAttribute("aria-label", s.lang_switch_title);

  document.querySelectorAll("[data-i18n]").forEach((el) => {
    const key = el.dataset.i18n;
    if (typeof s[key] === "string") {
      el.textContent = s[key];
    }
  });
  document.querySelectorAll("[data-i18n-placeholder]").forEach((el) => {
    const key = el.dataset.i18nPlaceholder;
    if (typeof s[key] === "string") el.placeholder = s[key];
  });
  document.querySelectorAll("[data-i18n-aria]").forEach((el) => {
    const key = el.dataset.i18nAria;
    if (typeof s[key] === "string") el.setAttribute("aria-label", s[key]);
  });
  document.querySelectorAll("[data-i18n-title]").forEach((el) => {
    const key = el.dataset.i18nTitle;
    if (typeof s[key] === "string") el.title = s[key];
  });

  if (stegoPath) {
    stegoNameEl.textContent = basename(stegoPath);
  }
  if (carrierPath) {
    carrierNameEl.textContent = basename(carrierPath);
  }
  renderCarrierInfo();
  renderItems();
  updatePasswordMatch();
}

langSwitchBtn.addEventListener("click", () => {
  const next = currentLang === "es" ? "en" : "es";
  saveLang(next);
  applyLanguage(next);
});

// ---------- Utilidades ----------

function makeCopyButton(labelKey, value) {
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "btn-copy";
  btn.textContent = t()[labelKey];
  btn.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(value);
      btn.textContent = t().copied;
      setTimeout(() => {
        btn.textContent = t()[labelKey];
      }, 1500);
    } catch {
      btn.textContent = t().copy_unavailable;
      setTimeout(() => {
        btn.textContent = t()[labelKey];
      }, 1500);
    }
  });
  return btn;
}

function extBadge(name) {
  const dot = name.lastIndexOf(".");
  if (dot <= 0 || dot === name.length - 1) return t().thumb_default;
  return name.slice(dot + 1, dot + 5).toUpperCase();
}

// Mientras el backend trabaja (Argon2 tarda): bloqueamos controles interactivos
// (guardando su estado previo para no reactivar p. ej. LSB si no era imagen)
// y mostramos aviso para que nadie lance una segunda operación ni edite la lista.
async function whileBusy(btn, resultEl, work) {
  const controls = document.querySelectorAll(
    ".tabs button, #lang-switch, main button, main input, main textarea"
  );
  const prevDisabled = new Map();
  controls.forEach((el) => {
    prevDisabled.set(el, el.disabled);
    el.disabled = true;
  });
  btn.disabled = true;
  resultEl.className = "result";
  resultEl.textContent = t().busy_msg;
  try {
    await work();
  } finally {
    controls.forEach((el) => {
      el.disabled = prevDisabled.get(el) ?? false;
    });
  }
}

function textDiv(className, text) {
  const d = document.createElement("div");
  if (className) d.className = className;
  d.textContent = text;
  return d;
}

function formatBytes(n) {
  const fmt = (x) => x.toLocaleString(t().locale, { maximumFractionDigits: 1 });
  if (n < 1024) return `${n} B`;
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
  return `${base}${t().default_out_suffix}.${ext}`;
}

function showResult(el, message, ok) {
  el.className = `result ${ok ? "ok" : "err"}`;
  el.textContent = message;
}

applyLanguage(currentLang);
