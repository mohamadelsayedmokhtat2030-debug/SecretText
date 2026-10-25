
"use strict";

function initSecretText() {
  const $ = (id) => document.getElementById(id);

  const requiredIds = [
    "message", "password", "encryptedOutput",
    "encryptedInput", "decryptPassword", "decryptedOutput",
    "encryptBtn", "decryptBtn", "copyBtn",
    "copyPlainBtn", "togglePassword",
    "encryptStatus", "decryptStatus"
  ];

  const missing = requiredIds.filter((id) => !$(id));

  if (missing.length) {
    console.error("SecretText: عناصر HTML غير موجودة:", missing);
    alert("تعذر تشغيل SecretText. راجع عناصر HTML التالية: " + missing.join(", "));
    return;
  }

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
    for (let i = 0; i < bytes.length; i += 0x8000) {
      binary += String.fromCharCode(
        ...bytes.subarray(i, i + 0x8000)
      );
    }

    return btoa(binary)
      .replace(/\+/g, "-")
      .replace(/\//g, "_")
      .replace(/=+$/g, "");
  }

  function fromBase64Url(value) {
    if (!/^[A-Za-z0-9_-]+$/.test(value)) {
      throw new Error("تنسيق النص المشفر غير صحيح.");
    }

    const base64 = value.replace(/-/g, "+").replace(/_/g, "/");
    const padded = base64 + "=".repeat((4 - base64.length % 4) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);

    for (let i = 0; i < binary.length; i++) {
      bytes[i] = binary.charCodeAt(i);
    }

    return bytes;
  }

  async function deriveKey(secret, salt) {
    const material = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(secret),
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
      { name: "AES-GCM", length: 256 },
      false,
      ["encrypt", "decrypt"]
    );
  }

  async function encryptMessage(plainText, secret) {
    const salt = randomBytes(16);
    const iv = randomBytes(12);
    const key = await deriveKey(secret, salt);

    const ciphertext = await crypto.subtle.encrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      new TextEncoder().encode(plainText)
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

    if (parts.length !== 4 || parts[0] !== "ST1") {
      throw new Error("صيغة الرسالة المشفرة غير صحيحة.");
    }

    const salt = fromBase64Url(parts[1]);
    const iv = fromBase64Url(parts[2]);
    const ciphertext = fromBase64Url(parts[3]);

    if (salt.length !== 16 || iv.length !== 12 || ciphertext.length < 16) {
      throw new Error("بيانات التشفير غير صالحة.");
    }

    const key = await deriveKey(secret, salt);

    const plaintext = await crypto.subtle.decrypt(
      { name: "AES-GCM", iv, tagLength: 128 },
      key,
      ciphertext
    );

    return new TextDecoder("utf-8", { fatal: true }).decode(plaintext);
  }

  function copyText(text, statusId) {
    if (!text) {
      showStatus(statusId, "مفيش نص لنسخه لسه.", "error");
      return;
    }

    if (!navigator.clipboard?.writeText) {
      showStatus(
        statusId,
        "النسخ التلقائي غير متاح. حدد النص وانسخه يدويًا.",
        "info"
      );
      return;
    }

    navigator.clipboard.writeText(text)
      .then(() => showStatus(statusId, "تم نسخ النص بنجاح. ✅", "success"))
      .catch(() => showStatus(
        statusId,
        "حدد النص وانسخه يدويًا.",
        "info"
      ));
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
        "كلمة المرور لازم تكون 12 حرفًا على الأقل.",
        "error"
      );
      password.focus();
      return;
    }

    if (!globalThis.crypto?.subtle) {
      showStatus(
        "encryptStatus",
        "التشفير غير متاح. افتح الموقع عبر HTTPS.",
        "error"
      );
      return;
    }

    setBusy(encryptBtn, true, "جارٍ التشفير...", "🔒 تشفير الرسالة");

    try {
      encryptedOutput.value = await encryptMessage(text, secret);
      showStatus(
        "encryptStatus",
        "تم التشفير بنجاح. شارك النص المشفر فقط، وكلمة المرور بطريقة منفصلة.",
        "success"
      );
    } catch (error) {
      console.error("SecretText encryption error:", error);
      showStatus("encryptStatus", "فشل التشفير. افتح وحدة التحكم لمعرفة السبب.", "error");
    } finally {
      setBusy(encryptBtn, false, "", "🔒 تشفير الرسالة");
    }
  });

  decryptBtn.addEventListener("click", async () => {
    clearStatus("decryptStatus");

    const payload = encryptedInput.value.trim();
    const secret = decryptPassword.value;

    if (!payload) {
      showStatus("decryptStatus", "الصق النص المشفر الأول.", "error");
      encryptedInput.focus();
      return;
    }

    if (!secret) {
      showStatus("decryptStatus", "اكتب كلمة المرور المتفق عليها.", "error");
      decryptPassword.focus();
      return;
    }

    if (!globalThis.crypto?.subtle) {
      showStatus("decryptStatus", "فك التشفير يحتاج إلى HTTPS.", "error");
      return;
    }

    setBusy(decryptBtn, true, "جارٍ فك التشفير...", "🔓 فك تشفير الرسالة");

    try {
      decryptedOutput.value = await decryptMessage(payload, secret);
      showStatus("decryptStatus", "تم فك التشفير بنجاح. ✅", "success");
    } catch (error) {
      console.error("SecretText decryption error:", error);
      decryptedOutput.value = "";
      showStatus(
        "decryptStatus",
        "تعذر فك التشفير. راجع كلمة المرور والنص المشفر.",
        "error"
      );
    } finally {
      setBusy(decryptBtn, false, "", "🔓 فك تشفير الرسالة");
    }
  });

  $("copyBtn").addEventListener("click", () =>
    copyText(encryptedOutput.value, "encryptStatus")
  );

  $("copyPlainBtn").addEventListener("click", () =>
    copyText(decryptedOutput.value, "decryptStatus")
  );

  $("togglePassword").addEventListener("click", () => {
    const hidden = password.type === "password";
    password.type = hidden ? "text" : "password";
    $("togglePassword").textContent = hidden ? "إخفاء" : "إظهار";
  });

  message.addEventListener("input", () => clearStatus("encryptStatus"));
  password.addEventListener("input", () => clearStatus("encryptStatus"));
  encryptedInput.addEventListener("input", () => clearStatus("decryptStatus"));
  decryptPassword.addEventListener("input", () => clearStatus("decryptStatus"));

  console.info("SecretText initialized successfully.");
}

if (document.readyState === "loading") {
  document.addEventListener("DOMContentLoaded", initSecretText, { once: true });
} else {
  initSecretText();
}
