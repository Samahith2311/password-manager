// ---------- Settings ----------
const STORAGE_KEY = "vaultly_meta";
const PBKDF2_ITERATIONS = 600000;
const VERIFIER_TEXT = "vault-ok";

// The encryption key lives only in memory while the vault is unlocked.
let sessionKey = null;

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
// Turn the master password + salt into an AES-256 key.
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

// Encrypt text with a fresh random IV every time.
async function encryptText(key, text) {
  const iv = crypto.getRandomValues(new Uint8Array(12));
  const cipher = await crypto.subtle.encrypt(
    { name: "AES-GCM", iv },
    key,
    encoder.encode(text)
  );
  return { iv: toBase64(iv), data: toBase64(cipher) };
}

// Throws an error if the key is wrong or the data was changed.
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

// ---------- Screens ----------
const screens = {
  setup: document.getElementById("setup-screen"),
  unlock: document.getElementById("unlock-screen"),
  vault: document.getElementById("vault-screen"),
};

function showScreen(name) {
  Object.entries(screens).forEach(([key, el]) => {
    el.hidden = key !== name;
  });
  const firstInput = screens[name].querySelector("input");
  if (firstInput) firstInput.focus();
}

// ---------- Create vault ----------
document.getElementById("setup-form").addEventListener("submit", async (event) => {
  event.preventDefault();
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

  saveMeta({
    salt: toBase64(salt),
    iterations: PBKDF2_ITERATIONS,
    verifier,
  });

  sessionKey = key;
  event.target.reset();
  showScreen("vault");
});

// ---------- Unlock vault ----------
document.getElementById("unlock-form").addEventListener("submit", async (event) => {
  event.preventDefault();
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
  event.target.reset();
  showScreen("vault");
});

// ---------- Lock vault ----------
document.getElementById("lock-btn").addEventListener("click", () => {
  sessionKey = null;
  showScreen("unlock");
});

// ---------- Erase vault (useful while testing) ----------
document.getElementById("erase-btn").addEventListener("click", () => {
  const sure = confirm("This permanently deletes your vault. Continue?");
  if (!sure) return;
  localStorage.removeItem(STORAGE_KEY);
  sessionKey = null;
  showScreen("setup");
});

// ---------- Start ----------
showScreen(loadMeta() ? "unlock" : "setup");