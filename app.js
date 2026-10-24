
"use strict";

const $ = (id) => document.getElementById(id);

const message = $("message");
const password = $("password");
const encryptedOutput = $("encryptedOutput");
const encryptedInput = $("encryptedInput");
const decryptPassword = $("decryptPassword");
const decryptedOutput = $("decryptedOutput");

const encryptBtn = $("encryptBtn");
const decryptBtn = $("decryptBtn");

const ITERATIONS = 600000;
const MIN_PASSWORD_LENGTH = 12;
const FORMAT_PREFIX = "ST1.";

function showStatus(id, text, type = "info") {
  const element = $(id);
  element.textContent = text;
  element.className = "status show " + type;
}

function clearStatus(id) {
  const element = $(id);
  element.textContent = "";
  element.className = "status";
}

function randomBytes(length) {
  const bytes = new Uint8Array(length);
  crypto.getRandomValues(bytes);
  return bytes;
}

function toBase64Url(bytes) {
  let binary = "";
  const chunkSize = 0x8000;

  for (let i = 0; i < bytes.length; i += chunkSize) {
    binary += String.fromCharCode(
      ...bytes.subarray(i, i + chunkSize)
    );
  }

  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

function fromBase64Url(value) {
  if (!/^[A-Za-z0-9_-]+$/.test(value)) {
    throw new Error("تنسيق النص المشفّر غير صحيح.");
  }

  const base64 = value
    .replace(/-/g, "+")
    .replace(/_/g, "/");

  const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

async function deriveKey(secret, salt) {
  const encodedPassword = new TextEncoder().encode(secret);

  const material = await crypto.subtle.importKey(
    "raw",
    encodedPassword,
    "PBKDF2",
    false,
    ["deriveKey"]
  );

  return crypto.subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: ITERATIONS,
      hash: "SHA-256"
    },
    material,
    {
      name: "AES-GCM",
      length: 256
    },
    false,
    ["encrypt", "decrypt"]
  );
}

async function encryptMessage(plainText, secret) {
  const salt = randomBytes(16);
  const iv = randomBytes(12);
  const key = await deriveKey(secret, salt);

  const encodedMessage = new TextEncoder().encode(plainText);

  const ciphertext = await crypto.subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128
    },
    key,
    encodedMessage
  );

  return [
    "ST1",
    toBase64Url(salt),
    toBase64Url(iv),
    toBase64Url(new Uint8Array(ciphertext))
  ].join(".");
}

async function decryptMessage(payload, secret) {
  const parts = payload.trim().split(".");

  if (
    parts.length !== 4 ||
    parts[0] !== "ST1"
  ) {
    throw new Error(
      "صيغة الرسالة غير صحيحة. تأكد من نسخ النص كاملًا."
    );
  }

  const salt = fromBase64Url(parts[1]);
  const iv = fromBase64Url(parts[2]);
  const ciphertext = fromBase64Url(parts[3]);

  if (salt.length !== 16 || iv.length !== 12) {
    throw new Error("بيانات التشفير غير صالحة.");
  }

  if (ciphertext.length < 16) {
    throw new Error("النص المشفّر ناقص أو غير صالح.");
  }

  const key = await deriveKey(secret, salt);

  const plaintext = await crypto.subtle.decrypt(
    {
      name: "AES-GCM",
      iv,
      tagLength: 128
    },
    key,
    ciphertext
  );

  return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
}

async function copyText(text, statusId) {
  if (!text) {
    showStatus(statusId, "مفيش نص لنسخه لسه.", "error");
    return;
  }

  try {
    await navigator.clipboard.writeText(text);
    showStatus(statusId, "تم نسخ النص بنجاح. ✅", "success");
  } catch {
    showStatus(
      statusId,
      "المتصفح منع النسخ التلقائي. اضغط مطولًا على النص وحدده ثم انسخه.",
      "info"
    );
  }
}

function setBusy(button, busy, busyText, normalText) {
  button.disabled = busy;
  button.textContent = busy ? busyText : normalText;
}

encryptBtn.addEventListener("click", async () => {
  clearStatus("encryptStatus");

  const text = message.value;
  const secret = password.value;

  if (!text.trim()) {
    showStatus("encryptStatus", "اكتب الرسالة الأول.", "error");
    message.focus();
    return;
  }

  if (secret.length < MIN_PASSWORD_LENGTH) {
    showStatus(
      "encryptStatus",
      "كلمة المرور لازم تكون 12 حرفًا على الأقل. اختار كلمة قوية وصعبة التخمين.",
      "error"
    );
    password.focus();
    return;
  }

  if (!globalThis.crypto?.subtle) {
    showStatus(
      "encryptStatus",
      "التشفير غير متاح في سياق التشغيل الحالي. افتح الموقع عبر HTTPS أو localhost.",
      "error"
    );
    return;
  }

  setBusy(encryptBtn, true, "جارٍ التشفير...", "🔒 تشفير الرسالة");

  try {
    const result = await encryptMessage(text, secret);
    encryptedOutput.value = result;

    showStatus(
      "encryptStatus",
      "تم تشفير الرسالة بنجاح. ابعت النص المشفّر فقط، وشارك كلمة المرور بطريقة منفصلة.",
      "success"
    );
  } catch (error) {
    console.error(error);
    showStatus(
      "encryptStatus",
      "حصلت مشكلة أثناء التشفير. تأكد من اتصال المتصفح الآمن ثم حاول مجددًا.",
      "error"
    );
  } finally {
    setBusy(encryptBtn, false, "", "🔒 تشفير الرسالة");
  }
});

decryptBtn.addEventListener("click", async () => {
  clearStatus("decryptStatus");

  const payload = encryptedInput.value.trim();
  const secret = decryptPassword.value;

  if (!payload) {
    showStatus(
      "decryptStatus",
      "الصق النص المشفّر الأول.",
      "error"
    );
    encryptedInput.focus();
    return;
  }

  if (!secret) {
    showStatus(
      "decryptStatus",
      "اكتب كلمة المرور المتفق عليها.",
      "error"
    );
    decryptPassword.focus();
    return;
  }

  if (!globalThis.crypto?.subtle) {
    showStatus(
      "decryptStatus",
      "فك التشفير يحتاج إلى HTTPS أو localhost في المتصفح.",
      "error"
    );
    return;
  }

  setBusy(decryptBtn, true, "جارٍ فك التشفير...", "🔓 فك تشفير الرسالة");

  try {
    const result = await decryptMessage(payload, secret);
    decryptedOutput.value = result;

    showStatus(
      "decryptStatus",
      "تم فك التشفير بنجاح. الرسالة الأصلية ظهرت بالأسفل. ✅",
      "success"
    );
  } catch (error) {
    console.error(error);

    decryptedOutput.value = "";

    showStatus(
      "decryptStatus",
      "تعذّر فك التشفير. راجع كلمة المرور والنص المنسوخ؛ قد يكون أحدهما غير صحيح أو الرسالة تالفة.",
      "error"
    );
  } finally {
    setBusy(decryptBtn, false, "", "🔓 فك تشفير الرسالة");
  }
});

$("copyBtn").addEventListener("click", () => {
  copyText(encryptedOutput.value, "encryptStatus");
});

$("copyPlainBtn").addEventListener("click", () => {
  copyText(decryptedOutput.value, "decryptStatus");
});

$("togglePassword").addEventListener("click", () => {
  const button = $("togglePassword");
  const isHidden = password.type === "password";

  password.type = isHidden ? "text" : "password";
  button.textContent = isHidden ? "إخفاء" : "إظهار";
});

message.addEventListener("input", () => {
  clearStatus("encryptStatus");
});

password.addEventListener("input", () => {
  clearStatus("encryptStatus");
});

encryptedInput.addEventListener("input", () => {
  clearStatus("decryptStatus");
});

decryptPassword.addEventListener("input", () => {
  clearStatus("decryptStatus");
});
