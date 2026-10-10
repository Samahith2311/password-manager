// ---------- Settings ----------
const STORAGE_KEY = "vaultly_meta";         // salt + encrypted test string
const DATA_KEY = "vaultly_data";            // encrypted entries
const SETTINGS_KEY = "vaultly_settings";    // auto-lock time and theme (not secret)
const PBKDF2_ITERATIONS = 600000;
const VERIFIER_TEXT = "vault-ok";
const CLIPBOARD_CLEAR_MS = 20000;           // clear copied password after 20 seconds
const AUTOLOCK_OPTIONS = [1, 2, 5, 10, 15, 30];
const DEFAULT_AUTOLOCK_MINUTES = 5;
const BACKUP_APP_NAME = "vaultly-backup";
const MAX_IMPORT_BYTES = 10 * 1024 * 1024;  // refuse files bigger than 10 MB
const PWNED_RANGE_URL = "https://api.pwnedpasswords.com/range/";
const OLD_PASSWORD_MS = 365 * 24 * 60 * 60 * 1000; // one year
const MAX_ISSUE_ROWS = 8;

// These live only in memory while the vault is unlocked.
let sessionKey = null;
let entries = [];
const revealed = new Set();       // ids of entries whose password is visible
const breachResults = new Map();  // entry id -> number of times seen in breaches

const encoder = new TextEncoder();
const decoder = new TextDecoder();

// ---------- Helpers: bytes <-> base64 ----------
function toBase64(bytes) {
  return btoa(String.fromCharCode(...new Uint8Array(bytes)));
}

function fromBase64(text) {
  return Uint8Array.from(atob(text), (c) => c.charCodeAt(0));
}

// ---------- Crypto ----------
async function deriveKey(password, salt, iterations) {
  const baseKey = await crypto.subtle.importKey(
    "raw",
    encoder.encode(password),
    "PBKDF2",
    false,
    ["deriveKey"]
  );
  return crypto.subtle.deriveKey(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptText(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(text)
  );
  return { iv: toBase64(iv), data: toBase64(cipher) };
}

async function decryptText(key, payload) {
  const plain = await crypto.subtle.decrypt(
    { name: "AES-GCM", iv: fromBase64(payload.iv) },
    key,
    fromBase64(payload.data)
  );
  return decoder.decode(plain);
}

// ---------- Storage ----------
function loadMeta() {
  const raw = localStorage.getItem(STORAGE_KEY);
  return raw ? JSON.parse(raw) : null;
}

function saveMeta(meta) {
  localStorage.setItem(STORAGE_KEY, JSON.stringify(meta));
}

// Encrypt all entries and save them as one blob.
async function saveEntries() {
  const payload = await encryptText(sessionKey, JSON.stringify(entries));
  localStorage.setItem(DATA_KEY, JSON.stringify(payload));
}

// Read and decrypt the saved entries (empty list if nothing is saved yet).
async function loadEntries() {
  const raw = localStorage.getItem(DATA_KEY);
  if (!raw) {
    entries = [];
    return;
  }
  const json = await decryptText(sessionKey, JSON.parse(raw));
  entries = JSON.parse(json);
}

// ---------- Settings storage ----------
function loadSettings() {
  try {
    const saved = JSON.parse(localStorage.getItem(SETTINGS_KEY) || "{}");
    return saved && typeof saved === "object" ? saved : {};
  } catch (err) {
    return {};
  }
}

// Save only the settings that changed, keeping the others.
function saveSettings(changes) {
  localStorage.setItem(SETTINGS_KEY, JSON.stringify({ ...loadSettings(), ...changes }));
}

function loadAutoLockMinutes() {
  const saved = loadSettings().autoLockMinutes;
  return AUTOLOCK_OPTIONS.includes(saved) ? saved : DEFAULT_AUTOLOCK_MINUTES;
}

let autoLockMinutes = loadAutoLockMinutes();

// ---------- Theme (light and dark) ----------
const themeBtn = document.getElementById("theme-btn");

function getTheme() {
  const saved = loadSettings().theme;
  if (saved === "dark" || saved === "light") return saved;
  return window.matchMedia("(prefers-color-scheme: dark)").matches ? "dark" : "light";
}

function applyTheme(theme) {
  document.documentElement.dataset.theme = theme;
  themeBtn.textContent = theme === "dark" ? "Light mode" : "Dark mode";
  themeBtn.setAttribute(
    "aria-label",
    theme === "dark" ? "Switch to light mode" : "Switch to dark mode"
  );
}

themeBtn.addEventListener("click", () => {
  const next = document.documentElement.dataset.theme === "dark" ? "light" : "dark";
  saveSettings({ theme: next });
  applyTheme(next);
});

// ---------- Screens ----------
const card = document.getElementById("card");
const lockNotice = document.getElementById("lock-notice");
const autoLockSelect = document.getElementById("autolock-select");
const screens = {
  setup: document.getElementById("setup-screen"),
  unlock: document.getElementById("unlock-screen"),
  vault: document.getElementById("vault-screen"),
};

function showScreen(name) {
  Object.entries(screens).forEach(([key, el]) => {
    el.hidden = key !== name;
  });
  card.classList.toggle("wide", name === "vault");
  const firstInput = screens[name].querySelector("input");
  if (firstInput && name !== "vault") firstInput.focus();
}

async function enterVault() {
  await loadEntries();
  searchInput.value = "";
  closeForm();
  renderEntries();
  autoLockSelect.value = String(autoLockMinutes);
  lockNotice.hidden = true;
  showScreen("vault");
  startAutoLockTimer();
}

// Lock the vault. "message" is an optional note shown on the unlock screen.
function leaveVault(message) {
  stopAutoLockTimer();
  if (clipboardTimer) clearClipboard();
  sessionKey = null;
  entries = [];
  revealed.clear();
  entryList.replaceChildren();
  dashboardBody.replaceChildren();
  closeForm();
  resetBackupUi();
  resetBreachUi();
  lockNotice.textContent = message || "";
  lockNotice.hidden = !message;
  showScreen("unlock");
}

// ---------- Auto-lock ----------
let lastActivity = Date.now();
let autoLockTimer = null;

function startAutoLockTimer() {
  stopAutoLockTimer();
  lastActivity = Date.now();
  autoLockTimer = setInterval(checkInactivity, 1000);
}

function stopAutoLockTimer() {
  clearInterval(autoLockTimer);
  autoLockTimer = null;
}

function checkInactivity() {
  const idleMs = Date.now() - lastActivity;
  if (idleMs >= autoLockMinutes * 60 * 1000) {
    const unit = autoLockMinutes === 1 ? "minute" : "minutes";
    leaveVault("Your vault was locked after " + autoLockMinutes + " " + unit + " of inactivity.");
  }
}

// Any of these counts as "the person is still here".
["mousemove", "keydown", "click", "scroll", "touchstart"].forEach((name) => {
  window.addEventListener(
    name,
    () => {
      lastActivity = Date.now();
    },
    { passive: true }
  );
});

autoLockSelect.addEventListener("change", () => {
  autoLockMinutes = Number(autoLockSelect.value);
  saveSettings({ autoLockMinutes });
  lastActivity = Date.now();
});

// ---------- Clipboard ----------
let clipboardTimer = null;

async function copyToClipboard(text) {
  await navigator.clipboard.writeText(text);
  clearTimeout(clipboardTimer);
  clipboardTimer = setTimeout(clearClipboard, CLIPBOARD_CLEAR_MS);
}

async function clearClipboard() {
  clearTimeout(clipboardTimer);
  clipboardTimer = null;
  try {
    await navigator.clipboard.writeText("");
  } catch (err) {
    // The browser only allows this while the page is focused. Nothing more to do.
  }
}

// ---------- Create vault ----------
document.getElementById("setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const password = document.getElementById("setup-password").value;
  const confirm = document.getElementById("setup-confirm").value;
  const errorEl = document.getElementById("setup-error");
  errorEl.textContent = "";

  if (password.length < 10) {
    errorEl.textContent = "Use at least 10 characters.";
    return;
  }
  if (password !== confirm) {
    errorEl.textContent = "The two passwords do not match.";
    return;
  }

  const salt = crypto.getRandomValues(new Uint8Array(16));
  const key = await deriveKey(password, salt, PBKDF2_ITERATIONS);
  const verifier = await encryptText(key, VERIFIER_TEXT);

  saveMeta({ salt: toBase64(salt), iterations: PBKDF2_ITERATIONS, verifier });

  sessionKey = key;
  form.reset();
  await enterVault();
});

// ---------- Unlock vault ----------
document.getElementById("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  const form = event.target;
  const password = document.getElementById("unlock-password").value;
  const errorEl = document.getElementById("unlock-error");
  errorEl.textContent = "";

  const meta = loadMeta();
  const key = await deriveKey(password, fromBase64(meta.salt), meta.iterations);

  try {
    const text = await decryptText(key, meta.verifier);
    if (text !== VERIFIER_TEXT) throw new Error("Wrong key");
  } catch (err) {
    errorEl.textContent = "Wrong master password. Try again.";
    return;
  }

  sessionKey = key;
  form.reset();
  await enterVault();
});

// ---------- Lock and erase ----------
document.getElementById("lock-btn").addEventListener("click", () => leaveVault());

document.getElementById("erase-btn").addEventListener("click", () => {
  const sure = confirm("This permanently deletes your vault and all entries. Continue?");
  if (!sure) return;
  localStorage.removeItem(STORAGE_KEY);
  localStorage.removeItem(DATA_KEY);
  sessionKey = null;
  entries = [];
  lockNotice.hidden = true;
  showScreen("setup");
});

// ---------- Entry form (add and edit) ----------
const entryForm = document.getElementById("entry-form");
const addBtn = document.getElementById("add-btn");
const cancelBtn = document.getElementById("cancel-btn");
const searchInput = document.getElementById("search");
const entryList = document.getElementById("entry-list");
const emptyMsg = document.getElementById("empty-msg");

const fields = {
  id: document.getElementById("entry-id"),
  title: document.getElementById("entry-title"),
  username: document.getElementById("entry-username"),
  password: document.getElementById("entry-password"),
  url: document.getElementById("entry-url"),
  category: document.getElementById("entry-category"),
  notes: document.getElementById("entry-notes"),
};

function openForm(entry) {
  entryForm.reset();
  fields.password.type = "password";
  fields.id.value = entry ? entry.id : "";
  if (entry) {
    fields.title.value = entry.title;
    fields.username.value = entry.username;
    fields.password.value = entry.password;
    fields.url.value = entry.url;
    fields.category.value = entry.category;
    fields.notes.value = entry.notes;
  }
  syncLengthLabel();
  updateStrength();
  clearBreachResult();
  entryForm.hidden = false;
  entryForm.scrollIntoView({ block: "start" });
  fields.title.focus();
}

function closeForm() {
  entryForm.reset();
  syncLengthLabel();
  updateStrength();
  clearBreachResult();
  entryForm.hidden = true;
}

addBtn.addEventListener("click", () => openForm(null));
cancelBtn.addEventListener("click", closeForm);

document.getElementById("entry-show").addEventListener("change", (event) => {
  fields.password.type = event.target.checked ? "text" : "password";
});

entryForm.addEventListener("submit", async (event) => {
  event.preventDefault();

  const data = {
    title: fields.title.value.trim(),
    username: fields.username.value.trim(),
    password: fields.password.value,
    url: fields.url.value.trim(),
    category: fields.category.value,
    notes: fields.notes.value.trim(),
  };

  const id = fields.id.value;
  if (id) {
    const index = entries.findIndex((e) => e.id === id);
    const old = entries[index];
    // Only a changed password resets the "last changed" date.
    const passwordChanged = old.password !== data.password;
    entries[index] = {
      ...old,
      ...data,
      updatedAt: passwordChanged ? Date.now() : old.updatedAt || old.createdAt || Date.now(),
    };
    breachResults.delete(id); // the password may have changed, so the old result is stale
  } else {
    entries.push({ id: crypto.randomUUID(), ...data, createdAt: Date.now(), updatedAt: Date.now() });
  }

  await saveEntries();
  closeForm();
  renderEntries();
});

// ---------- Show the list ----------
searchInput.addEventListener("input", renderEntries);

function matchesSearch(entry, query) {
  if (!query) return true;
  const text = [entry.title, entry.username, entry.url, entry.category].join(" ").toLowerCase();
  return text.includes(query);
}

function makeLine(className, text) {
  const p = document.createElement("p");
  p.className = className;
  p.textContent = text;
  return p;
}

function makeButton(label, onClick, extraClass) {
  const button = document.createElement("button");
  button.type = "button";
  button.className = "secondary " + (extraClass || "");
  button.textContent = label;
  button.addEventListener("click", onClick);
  return button;
}

function makeTag(text, extraClass) {
  const tag = document.createElement("span");
  tag.className = "tag " + (extraClass || "");
  tag.textContent = text;
  return tag;
}

function renderEntries() {
  renderDashboard();

  const query = searchInput.value.trim().toLowerCase();
  const visible = entries
    .filter((entry) => matchesSearch(entry, query))
    .sort((a, b) => a.title.localeCompare(b.title));

  entryList.replaceChildren();

  if (entries.length === 0) {
    emptyMsg.textContent = "Your vault is empty. Choose Add entry to save your first login.";
    emptyMsg.hidden = false;
    return;
  }
  if (visible.length === 0) {
    emptyMsg.textContent = "No entries match your search.";
    emptyMsg.hidden = false;
    return;
  }
  emptyMsg.hidden = true;

  visible.forEach((entry) => entryList.appendChild(buildEntryItem(entry)));
}

function buildEntryItem(entry) {
  const li = document.createElement("li");
  li.className = "entry";

  const top = document.createElement("div");
  top.className = "entry-top";
  const title = document.createElement("span");
  title.className = "entry-title";
  title.textContent = entry.title;

  const tags = document.createElement("span");
  tags.className = "tags";
  if (breachResults.has(entry.id)) {
    const count = breachResults.get(entry.id);
    if (count > 0) {
      tags.appendChild(makeTag("Seen " + count.toLocaleString() + " times in breaches", "tag-danger"));
    } else {
      tags.appendChild(makeTag("No breach found", "tag-ok"));
    }
  }
  tags.appendChild(makeTag(entry.category));

  top.append(title, tags);
  li.appendChild(top);

  if (entry.username) li.appendChild(makeLine("entry-line", entry.username));

  if (entry.url) {
    const p = document.createElement("p");
    p.className = "entry-line";
    if (/^https?:\/\//i.test(entry.url)) {
      const link = document.createElement("a");
      link.href = entry.url;
      link.target = "_blank";
      link.rel = "noopener noreferrer";
      link.textContent = entry.url;
      p.appendChild(link);
    } else {
      p.textContent = entry.url;
    }
    li.appendChild(p);
  }

  const isShown = revealed.has(entry.id);
  li.appendChild(
    makeLine("entry-line entry-password", isShown ? entry.password : "\u2022".repeat(10))
  );

  if (entry.notes) li.appendChild(makeLine("entry-line", entry.notes));

  const actions = document.createElement("div");
  actions.className = "entry-actions";

  actions.appendChild(
    makeButton(isShown ? "Hide" : "Show", () => {
      if (revealed.has(entry.id)) revealed.delete(entry.id);
      else revealed.add(entry.id);
      renderEntries();
    })
  );

  const copyButton = makeButton("Copy password", async () => {
    try {
      await copyToClipboard(entry.password);
      copyButton.textContent = "Copied. Clears in " + CLIPBOARD_CLEAR_MS / 1000 + "s";
    } catch (err) {
      copyButton.textContent = "Copy failed";
    }
    setTimeout(() => {
      copyButton.textContent = "Copy password";
    }, 2500);
  });
  actions.appendChild(copyButton);

  actions.appendChild(makeButton("Edit", () => openForm(entry)));

  actions.appendChild(
    makeButton(
      "Delete",
      async () => {
        if (!confirm('Delete "' + entry.title + '"? This cannot be undone.')) return;
        entries = entries.filter((e) => e.id !== entry.id);
        revealed.delete(entry.id);
        breachResults.delete(entry.id);
        await saveEntries();
        renderEntries();
      },
      "danger"
    )
  );

  li.appendChild(actions);
  return li;
}

// ---------- Security overview ----------
const dashboardBody = document.getElementById("dashboard-body");

// Work out which entries have problems, and an overall score from 0 to 100.
function analyzeVault() {
  // Group entries by password to find reuse.
  const byPassword = new Map();
  entries.forEach((entry) => {
    if (!entry.password) return;
    if (!byPassword.has(entry.password)) byPassword.set(entry.password, []);
    byPassword.get(entry.password).push(entry);
  });
  const reusedIds = new Set();
  byPassword.forEach((group) => {
    if (group.length > 1) group.forEach((entry) => reusedIds.add(entry.id));
  });

  const weak = [];
  const reused = [];
  const breached = [];
  const old = [];
  let penalty = 0;

  entries.forEach((entry) => {
    let entryPenalty = 0;

    if (estimateStrength(entry.password) <= 1) {
      weak.push(entry);
      entryPenalty += 0.6;
    }
    if (reusedIds.has(entry.id)) {
      reused.push(entry);
      entryPenalty += 0.6;
    }
    if ((breachResults.get(entry.id) || 0) > 0) {
      breached.push(entry);
      entryPenalty += 1;
    }
    const changedAt = entry.updatedAt || entry.createdAt || Date.now();
    if (Date.now() - changedAt > OLD_PASSWORD_MS) {
      old.push(entry);
      entryPenalty += 0.2;
    }

    penalty += Math.min(1, entryPenalty);
  });

  const score = entries.length
    ? Math.round(100 * (1 - penalty / entries.length))
    : 100;

  return { weak, reused, breached, old, score };
}

function scoreInfo(score) {
  if (score >= 90) return { label: "Excellent", cls: "s4" };
  if (score >= 75) return { label: "Good", cls: "s3" };
  if (score >= 50) return { label: "Needs work", cls: "s2" };
  return { label: "At risk", cls: "s0" };
}

// One block of the overview: a title, a count, and the entries with that problem.
function buildIssue(title, description, list, checked) {
  const section = document.createElement("div");
  section.className = "issue";

  const head = document.createElement("div");
  head.className = "issue-head";
  const name = document.createElement("span");
  name.textContent = title;

  let countTag;
  if (!checked) {
    countTag = makeTag("Not checked yet");
  } else if (list.length > 0) {
    countTag = makeTag(String(list.length), "tag-danger");
  } else {
    countTag = makeTag("None found", "tag-ok");
  }
  head.append(name, countTag);
  section.append(head, makeLine("issue-desc", description));

  if (checked && list.length > 0) {
    const ul = document.createElement("ul");
    ul.className = "issue-list";

    list.slice(0, MAX_ISSUE_ROWS).forEach((entry) => {
      const li = document.createElement("li");
      const label = document.createElement("span");
      label.textContent = entry.title + (entry.username ? " (" + entry.username + ")" : "");
      li.append(label, makeButton("Fix", () => openForm(entry)));
      ul.appendChild(li);
    });
    section.appendChild(ul);

    if (list.length > MAX_ISSUE_ROWS) {
      section.appendChild(makeLine("issue-more", "and " + (list.length - MAX_ISSUE_ROWS) + " more"));
    }
  }

  return section;
}

function renderDashboard() {
  dashboardBody.replaceChildren();

  if (entries.length === 0) {
    dashboardBody.appendChild(makeLine("hint", "Add some entries to see your security score."));
    return;
  }

  const result = analyzeVault();
  const info = scoreInfo(result.score);

  const row = document.createElement("div");
  row.className = "score-row";

  const number = document.createElement("span");
  number.className = "score-number";
  number.textContent = String(result.score);

  const label = document.createElement("span");
  label.className = "score-label";
  label.textContent = info.label;

  const bar = document.createElement("div");
  bar.className = "score-bar";
  const fill = document.createElement("div");
  fill.className = "score-fill " + info.cls;
  fill.style.width = result.score + "%";
  bar.appendChild(fill);

  row.append(number, label, bar);
  dashboardBody.appendChild(row);

  const breachChecked = breachResults.size > 0;

  dashboardBody.appendChild(
    buildIssue(
      "Breached passwords",
      breachChecked
        ? "Found in known data breaches. Change these first."
        : "Use Check for breaches above to scan your vault.",
      result.breached,
      breachChecked
    )
  );
  dashboardBody.appendChild(
    buildIssue(
      "Reused passwords",
      "The same password is on more than one entry. If one site is hacked, the others are at risk.",
      result.reused,
      true
    )
  );
  dashboardBody.appendChild(
    buildIssue(
      "Weak passwords",
      "Short or easy to guess. The generator can make a stronger one.",
      result.weak,
      true
    )
  );
  dashboardBody.appendChild(
    buildIssue(
      "Old passwords",
      "Not changed in over a year.",
      result.old,
      true
    )
  );
}

// ---------- Strength meter ----------
const strengthFill = document.getElementById("strength-fill");
const strengthLabel = document.getElementById("strength-label");

const COMMON_WORDS = [
  "password", "passw0rd", "123456", "qwerty", "letmein", "admin",
  "welcome", "iloveyou", "abc123", "monkey", "dragon", "login",
];

const STRENGTH_LABELS = ["Very weak", "Weak", "Fair", "Strong", "Very strong"];

// A rough estimate of how hard the password is to guess, in "bits".
function estimateStrength(password) {
  if (!password) return -1;

  let pool = 0;
  if (/[a-z]/.test(password)) pool += 26;
  if (/[A-Z]/.test(password)) pool += 26;
  if (/[0-9]/.test(password)) pool += 10;
  if (/[^A-Za-z0-9]/.test(password)) pool += 32;

  let bits = password.length * Math.log2(pool);

  // Lots of repeated characters make a password easier to guess.
  const uniqueRatio = new Set(password).size / password.length;
  bits *= 0.4 + 0.6 * uniqueRatio;

  if (/(.)\1{2,}/.test(password)) bits -= 10; // aaa, 111
  if (/(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|qwer|wert|erty|asdf|zxcv)/i.test(password)) {
    bits -= 15; // keyboard and number runs
  }
  const lower = password.toLowerCase();
  if (COMMON_WORDS.some((word) => lower.includes(word))) bits -= 20;

  if (bits < 28) return 0;
  if (bits < 40) return 1;
  if (bits < 60) return 2;
  if (bits < 80) return 3;
  return 4;
}

function updateStrength() {
  const level = estimateStrength(fields.password.value);
  if (level < 0) {
    strengthFill.style.width = "0";
    strengthFill.className = "strength-fill";
    strengthLabel.textContent = "";
    return;
  }
  strengthFill.style.width = (level + 1) * 20 + "%";
  strengthFill.className = "strength-fill level-" + level;
  strengthLabel.textContent = STRENGTH_LABELS[level];
}

fields.password.addEventListener("input", updateStrength);

// ---------- Password generator ----------
const genLength = document.getElementById("gen-length");
const genLengthValue = document.getElementById("gen-length-value");
const genError = document.getElementById("gen-error");

const CHARSETS = {
  lower: "abcdefghijklmnopqrstuvwxyz",
  upper: "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
  numbers: "0123456789",
  symbols: "!@#$%^&*()-_=+[]{};:,.?",
};

function syncLengthLabel() {
  genLengthValue.textContent = genLength.value;
}

genLength.addEventListener("input", syncLengthLabel);

// A secure random whole number from 0 to max - 1, with no bias.
function randomInt(max) {
  const limit = Math.floor(0x100000000 / max) * max;
  const buffer = new Uint32Array(1);
  do {
    crypto.getRandomValues(buffer);
  } while (buffer[0] >= limit);
  return buffer[0] % max;
}

function generatePassword(length, sets) {
  const allChars = sets.join("");

  // Take one character from each chosen set, then fill the rest.
  const chars = sets.map((set) => set[randomInt(set.length)]);
  while (chars.length < length) {
    chars.push(allChars[randomInt(allChars.length)]);
  }

  // Shuffle so the guaranteed characters are not always first.
  for (let i = chars.length - 1; i > 0; i--) {
    const j = randomInt(i + 1);
    [chars[i], chars[j]] = [chars[j], chars[i]];
  }
  return chars.join("");
}

document.getElementById("gen-btn").addEventListener("click", () => {
  const sets = [];
  if (document.getElementById("gen-lower").checked) sets.push(CHARSETS.lower);
  if (document.getElementById("gen-upper").checked) sets.push(CHARSETS.upper);
  if (document.getElementById("gen-numbers").checked) sets.push(CHARSETS.numbers);
  if (document.getElementById("gen-symbols").checked) sets.push(CHARSETS.symbols);

  if (sets.length === 0) {
    genError.textContent = "Choose at least one type of character.";
    return;
  }
  genError.textContent = "";

  fields.password.value = generatePassword(Number(genLength.value), sets);
  fields.password.type = "text";
  document.getElementById("entry-show").checked = true;
  updateStrength();
  clearBreachResult();
});

// ---------- Breach check (Have I Been Pwned, k-anonymity) ----------
const breachBtn = document.getElementById("breach-btn");
const breachResult = document.getElementById("breach-result");
const checkAllBtn = document.getElementById("check-all-btn");
const breachSummary = document.getElementById("breach-summary");

const rangeCache = new Map(); // first 5 hash characters -> Map(rest of hash -> count)

// The SHA-1 hash of the password, as uppercase hex text.
async function sha1Hex(text) {
  const buffer = await crypto.subtle.digest("SHA-1", encoder.encode(text));
  return Array.from(new Uint8Array(buffer))
    .map((byte) => byte.toString(16).padStart(2, "0"))
    .join("")
    .toUpperCase();
}

// Ask the service for every hash that starts with these 5 characters.
async function fetchRange(prefix) {
  if (rangeCache.has(prefix)) return rangeCache.get(prefix);

  const response = await fetch(PWNED_RANGE_URL + prefix);
  if (!response.ok) throw new Error("Breach service error " + response.status);

  const text = await response.text();
  const hashes = new Map();
  text.split("\n").forEach((line) => {
    const [suffix, count] = line.trim().split(":");
    if (suffix && count) hashes.set(suffix, Number(count));
  });

  rangeCache.set(prefix, hashes);
  return hashes;
}

// How many times this password appears in known breaches (0 means not found).
// Only the first 5 characters of the hash are ever sent over the network.
async function pwnedCount(password) {
  const hash = await sha1Hex(password);
  const hashes = await fetchRange(hash.slice(0, 5));
  return hashes.get(hash.slice(5)) || 0;
}

function setBreachResult(message, isError) {
  breachResult.textContent = message || "";
  breachResult.classList.toggle("is-error", Boolean(isError));
}

function clearBreachResult() {
  setBreachResult("");
}

// A changed password makes any earlier result out of date.
fields.password.addEventListener("input", clearBreachResult);

function resetBreachUi() {
  breachResults.clear();
  rangeCache.clear();
  breachSummary.textContent = "";
  breachSummary.classList.remove("is-error");
  checkAllBtn.disabled = false;
}

// --- Check the password typed in the form ---
breachBtn.addEventListener("click", async () => {
  const password = fields.password.value;
  if (!password) {
    setBreachResult("Enter a password first.", true);
    return;
  }

  breachBtn.disabled = true;
  setBreachResult("Checking...");

  try {
    const count = await pwnedCount(password);
    if (count > 0) {
      setBreachResult(
        "Seen " + count.toLocaleString() + " times in known data breaches. Choose a different password.",
        true
      );
    } else {
      setBreachResult("Not found in known breaches. That is good, but it does not guarantee it is safe.");
    }
  } catch (err) {
    setBreachResult("Could not check right now. Are you online?", true);
  }

  breachBtn.disabled = false;
});

// --- Check every entry in the vault ---
checkAllBtn.addEventListener("click", async () => {
  if (entries.length === 0) {
    breachSummary.textContent = "Your vault has no entries to check.";
    breachSummary.classList.add("is-error");
    return;
  }

  const snapshot = entries.slice();
  checkAllBtn.disabled = true;
  breachSummary.classList.remove("is-error");
  breachSummary.textContent = "Checking " + snapshot.length + " passwords...";

  let breached = 0;
  let failed = 0;

  for (const entry of snapshot) {
    try {
      const count = await pwnedCount(entry.password);
      breachResults.set(entry.id, count);
      if (count > 0) breached++;
    } catch (err) {
      failed++;
    }
  }

  // The vault may have been locked while we were checking.
  if (sessionKey === null) return;

  renderEntries();
  checkAllBtn.disabled = false;

  if (failed === snapshot.length) {
    breachSummary.textContent = "Could not reach the breach service. Check your internet connection.";
    breachSummary.classList.add("is-error");
    return;
  }

  let message;
  if (breached > 0) {
    message =
      breached + " of " + snapshot.length +
      " passwords appeared in known data breaches. Change those passwords as soon as you can.";
    breachSummary.classList.add("is-error");
  } else {
    message = "None of the checked passwords were found in known breaches.";
  }
  if (failed > 0) message += " " + failed + " could not be checked.";
  breachSummary.textContent = message;
});

// ---------- Backup and import ----------
const backupPanel = document.getElementById("backup-panel");
const exportBtn = document.getElementById("export-btn");
const importBtn = document.getElementById("import-btn");
const importFile = document.getElementById("import-file");
const restoreForm = document.getElementById("restore-form");
const restoreFileName = document.getElementById("restore-file-name");
const restorePassword = document.getElementById("restore-password");
const backupStatus = document.getElementById("backup-status");

let pendingBackup = null; // a backup file waiting for its password

function setBackupStatus(message, isError) {
  backupStatus.textContent = message || "";
  backupStatus.classList.toggle("is-error", Boolean(isError));
}

function hideRestoreForm() {
  pendingBackup = null;
  restoreForm.reset();
  restoreForm.hidden = true;
}

function resetBackupUi() {
  hideRestoreForm();
  setBackupStatus("");
  backupPanel.open = false;
}

// --- Cleaning up imported entries ---
function str(value) {
  return typeof value === "string" ? value : "";
}

function categoryNames() {
  return Array.from(fields.category.options).map((option) => option.value);
}

function normalizeEntry(raw) {
  const category = categoryNames().includes(raw.category) ? raw.category : "Other";
  return {
    id: str(raw.id) || crypto.randomUUID(),
    title: str(raw.title).trim() || "Untitled",
    username: str(raw.username).trim(),
    password: str(raw.password),
    url: str(raw.url).trim(),
    category,
    notes: str(raw.notes).trim(),
    createdAt: Number(raw.createdAt) || Date.now(),
    updatedAt: Number(raw.updatedAt) || Date.now(),
  };
}

function entryKey(entry) {
  return [entry.title, entry.username, entry.url].map((s) => s.toLowerCase()).join("|");
}

// Add new entries and skip any that already exist (same title, username and website).
function mergeEntries(incoming) {
  const keys = new Set(entries.map(entryKey));
  const ids = new Set(entries.map((e) => e.id));
  let added = 0;
  let skipped = 0;

  incoming.forEach((raw) => {
    if (!raw || typeof raw !== "object") {
      skipped++;
      return;
    }
    const entry = normalizeEntry(raw);
    const key = entryKey(entry);
    if (keys.has(key)) {
      skipped++;
      return;
    }
    if (ids.has(entry.id)) entry.id = crypto.randomUUID();
    keys.add(key);
    ids.add(entry.id);
    entries.push(entry);
    added++;
  });

  return { added, skipped };
}

function plural(count, word) {
  return count + " " + word + (count === 1 ? "" : "s");
}

// --- Export ---
exportBtn.addEventListener("click", async () => {
  if (entries.length === 0) {
    setBackupStatus("There is nothing to export yet.", true);
    return;
  }

  const meta = loadMeta();
  const data = await encryptText(sessionKey, JSON.stringify(entries));
  const backup = {
    app: BACKUP_APP_NAME,
    version: 1,
    createdAt: new Date().toISOString(),
    salt: meta.salt,
    iterations: meta.iterations,
    data,
  };

  const blob = new Blob([JSON.stringify(backup)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = "vaultly-backup-" + new Date().toISOString().slice(0, 10) + ".json";
  document.body.appendChild(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(url), 1000);

  setBackupStatus(
    "Backup downloaded with " + plural(entries.length, "entry").replace("entrys", "entries") +
    ". To restore it you will need the master password you are using right now."
  );
});

// --- Choosing a file to import ---
importBtn.addEventListener("click", () => {
  importFile.value = "";
  importFile.click();
});

importFile.addEventListener("change", async () => {
  const file = importFile.files[0];
  if (!file) return;

  hideRestoreForm();
  setBackupStatus("");

  if (file.size > MAX_IMPORT_BYTES) {
    setBackupStatus("That file is too large to import.", true);
    return;
  }

  const text = await file.text();

  if (/\.csv$/i.test(file.name)) {
    await importCsv(text);
  } else if (/\.json$/i.test(file.name)) {
    prepareRestore(file.name, text);
  } else {
    setBackupStatus("Choose a .json backup or a .csv passwords file.", true);
  }
});

// --- Restore a Vaultly backup ---
function isValidBackup(backup) {
  return (
    backup &&
    backup.app === BACKUP_APP_NAME &&
    backup.version === 1 &&
    typeof backup.salt === "string" &&
    Number.isInteger(backup.iterations) &&
    backup.iterations >= 100000 &&
    backup.iterations <= 5000000 &&
    backup.data &&
    typeof backup.data.iv === "string" &&
    typeof backup.data.data === "string"
  );
}

function prepareRestore(fileName, text) {
  let backup;
  try {
    backup = JSON.parse(text);
  } catch (err) {
    backup = null;
  }

  if (!isValidBackup(backup)) {
    setBackupStatus("This does not look like a Vaultly backup file.", true);
    return;
  }

  pendingBackup = backup;
  restoreFileName.textContent = "Backup file: " + fileName;
  restoreForm.hidden = false;
  restorePassword.focus();
}

restoreForm.addEventListener("submit", async (event) => {
  event.preventDefault();
  if (!pendingBackup) return;

  let incoming;
  try {
    const key = await deriveKey(
      restorePassword.value,
      fromBase64(pendingBackup.salt),
      pendingBackup.iterations
    );
    const json = await decryptText(key, pendingBackup.data);
    incoming = JSON.parse(json);
    if (!Array.isArray(incoming)) throw new Error("Unexpected backup contents");
  } catch (err) {
    restorePassword.value = "";
    setBackupStatus("Could not open this backup. Check the password and the file.", true);
    return;
  }

  const result = mergeEntries(incoming);
  await saveEntries();
  renderEntries();
  hideRestoreForm();
  setBackupStatus(
    "Restored " + plural(result.added, "entry").replace("entrys", "entries") +
    ". Skipped " + plural(result.skipped, "duplicate") + "."
  );
});

document.getElementById("restore-cancel").addEventListener("click", () => {
  hideRestoreForm();
  setBackupStatus("");
});

// --- Import a passwords CSV (Chrome, Edge and similar) ---
// Reads CSV text, including quoted fields that contain commas or line breaks.
function parseCsv(text) {
  if (text.charCodeAt(0) === 0xfeff) text = text.slice(1); // remove byte order mark

  const rows = [];
  let row = [];
  let field = "";
  let inQuotes = false;

  for (let i = 0; i < text.length; i++) {
    const ch = text[i];

    if (inQuotes) {
      if (ch === '"') {
        if (text[i + 1] === '"') {
          field += '"';
          i++;
        } else {
          inQuotes = false;
        }
      } else {
        field += ch;
      }
    } else if (ch === '"') {
      inQuotes = true;
    } else if (ch === ",") {
      row.push(field);
      field = "";
    } else if (ch === "\n" || ch === "\r") {
      if (ch === "\r" && text[i + 1] === "\n") i++;
      row.push(field);
      field = "";
      rows.push(row);
      row = [];
    } else {
      field += ch;
    }
  }

  if (field !== "" || row.length > 0) {
    row.push(field);
    rows.push(row);
  }

  return rows.filter((r) => r.some((cell) => cell.trim() !== ""));
}

function websiteName(url) {
  try {
    return new URL(url).hostname.replace(/^www\./, "");
  } catch (err) {
    return url;
  }
}

async function importCsv(text) {
  const rows = parseCsv(text);
  if (rows.length < 2) {
    setBackupStatus("That CSV file has no entries.", true);
    return;
  }

  const headers = rows[0].map((h) => h.trim().toLowerCase());
  const find = (names) => headers.findIndex((h) => names.includes(h));

  const iTitle = find(["name", "title", "login_name"]);
  const iUrl = find(["url", "login_uri", "website", "origin"]);
  const iUser = find(["username", "login_username", "user"]);
  const iPass = find(["password", "login_password"]);
  const iNote = find(["note", "notes", "extra"]);

  if (iPass === -1 || (iUrl === -1 && iTitle === -1)) {
    setBackupStatus(
      "This CSV is not recognized. It needs columns like name, url, username and password.",
      true
    );
    return;
  }

  const incoming = [];
  let noPassword = 0;

  rows.slice(1).forEach((row) => {
    const get = (index) => (index >= 0 ? (row[index] || "").trim() : "");
    const password = row[iPass] || "";
    if (!password) {
      noPassword++;
      return;
    }
    const url = get(iUrl);
    incoming.push({
      title: get(iTitle) || websiteName(url),
      url,
      username: get(iUser),
      password,
      notes: get(iNote),
      category: "Other",
    });
  });

  const result = mergeEntries(incoming);
  await saveEntries();
  renderEntries();

  setBackupStatus(
    "Imported " + plural(result.added, "entry").replace("entrys", "entries") +
    ". Skipped " + plural(result.skipped, "duplicate") +
    " and " + plural(noPassword, "row") + " without a password. " +
    "Delete the CSV file now, because it holds your passwords as plain text."
  );
}

// ---------- Start ----------
applyTheme(getTheme());
showScreen(loadMeta() ? "unlock" : "setup");