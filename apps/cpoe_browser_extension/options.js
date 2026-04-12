/**
 * CPoE Browser Extension — Options Script
 */

const DEFAULT_SITES = {
  "google-docs": { label: "Google Docs", enabled: true },
  "overleaf": { label: "Overleaf", enabled: true },
  "medium": { label: "Medium", enabled: true },
  "notion": { label: "Notion", enabled: true },
  "craft": { label: "Craft", enabled: true },
  "coda": { label: "Coda", enabled: true },
  "clickup": { label: "ClickUp Docs", enabled: true },
  "nuclino": { label: "Nuclino", enabled: true },
  "stackedit": { label: "StackEdit", enabled: true },
  "hackmd": { label: "HackMD", enabled: true },
  "hemingway": { label: "Hemingway Editor", enabled: true },
  "quillbot": { label: "QuillBot", enabled: false },
  "etherpad": { label: "Etherpad", enabled: true },
  "riseup-pad": { label: "Riseup Pad", enabled: true },
  "write-as": { label: "Write.as", enabled: true },
  "wordpress": { label: "WordPress", enabled: true },
  "ghost": { label: "Ghost", enabled: true },
  "substack": { label: "Substack", enabled: true },
};

const DEFAULTS = {
  autoWitness: false,
  checkpointInterval: 30,
  contentTier: "enhanced",
  captureJitter: true,
  enabledSites: Object.fromEntries(
    Object.entries(DEFAULT_SITES).map(([k, v]) => [k, v.enabled])
  ),
  customDomains: [],
};

const elements = {
  autoWitness: document.getElementById("auto-witness"),
  checkpointInterval: document.getElementById("checkpoint-interval"),
  contentTier: document.getElementById("content-tier"),
  captureJitter: document.getElementById("capture-jitter"),
  btnSave: document.getElementById("btn-save"),
  saveStatus: document.getElementById("save-status"),
  siteList: document.getElementById("site-list"),
  customDomainsList: document.getElementById("custom-domains-list"),
  customDomainInput: document.getElementById("custom-domain-input"),
  btnAddDomain: document.getElementById("btn-add-domain"),
};

let currentCustomDomains = [];

function renderBuiltinSites(enabledSites) {
  elements.siteList.innerHTML = "";
  for (const [key, info] of Object.entries(DEFAULT_SITES)) {
    const label = document.createElement("label");
    label.className = "site-toggle";
    const input = document.createElement("input");
    input.type = "checkbox";
    input.dataset.site = key;
    input.checked = enabledSites?.[key] ?? info.enabled;
    label.appendChild(input);
    label.appendChild(document.createTextNode(" " + info.label));
    elements.siteList.appendChild(label);
  }
}

function renderCustomDomains() {
  elements.customDomainsList.innerHTML = "";
  for (const domain of currentCustomDomains) {
    const row = document.createElement("div");
    row.className = "custom-domain-row";

    const span = document.createElement("span");
    span.className = "custom-domain-name";
    span.textContent = domain;

    const btn = document.createElement("button");
    btn.className = "btn-remove";
    btn.textContent = "\u00d7";
    btn.title = "Remove " + domain;
    btn.addEventListener("click", () => {
      currentCustomDomains = currentCustomDomains.filter((d) => d !== domain);
      renderCustomDomains();
    });

    row.appendChild(span);
    row.appendChild(btn);
    elements.customDomainsList.appendChild(row);
  }
}

function addCustomDomain() {
  let raw = elements.customDomainInput.value.trim();
  if (!raw) return;

  // Normalize: strip protocol, trailing slashes
  raw = raw.replace(/^https?:\/\//, "").replace(/\/+$/, "");

  // Basic validation: must look like a domain
  if (!/^[a-zA-Z0-9*][a-zA-Z0-9.*-]+\.[a-zA-Z]{2,}$/.test(raw)) {
    elements.saveStatus.textContent = "Invalid domain";
    setTimeout(() => { elements.saveStatus.textContent = ""; }, 2000);
    return;
  }

  if (!currentCustomDomains.includes(raw)) {
    currentCustomDomains.push(raw);
    renderCustomDomains();
  }
  elements.customDomainInput.value = "";
}

async function loadSettings() {
  const result = await chrome.storage.local.get(Object.keys(DEFAULTS));
  const settings = { ...DEFAULTS, ...result };

  elements.autoWitness.checked = settings.autoWitness;
  elements.checkpointInterval.value = settings.checkpointInterval;
  elements.contentTier.value = settings.contentTier;
  elements.captureJitter.checked = settings.captureJitter;

  renderBuiltinSites(settings.enabledSites);

  currentCustomDomains = settings.customDomains || [];
  renderCustomDomains();
}

async function saveSettings() {
  const enabledSites = {};
  document.querySelectorAll(".site-toggle input[data-site]").forEach((input) => {
    enabledSites[input.dataset.site] = input.checked;
  });

  const settings = {
    autoWitness: elements.autoWitness.checked,
    checkpointInterval: parseInt(elements.checkpointInterval.value, 10) || 30,
    contentTier: elements.contentTier.value,
    captureJitter: elements.captureJitter.checked,
    enabledSites,
    customDomains: currentCustomDomains,
  };

  await chrome.storage.local.set(settings);

  elements.saveStatus.textContent = "Saved";
  setTimeout(() => { elements.saveStatus.textContent = ""; }, 2000);
}

elements.btnSave.addEventListener("click", saveSettings);
elements.btnAddDomain.addEventListener("click", addCustomDomain);
elements.customDomainInput.addEventListener("keydown", (e) => {
  if (e.key === "Enter") { e.preventDefault(); addCustomDomain(); }
});

loadSettings();
