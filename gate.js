(() => {
  "use strict";

  const form = document.querySelector("#gate-form");
  const input = document.querySelector("#invite-code");
  const button = document.querySelector("#unlock-button");
  const status = document.querySelector("#gate-status");

  function setStatus(message, kind = "") {
    status.textContent = message;
    status.className = `status ${kind}`.trim();
  }

  function fromBase64(value) {
    const binary = atob(value);
    const bytes = new Uint8Array(binary.length);
    for (let index = 0; index < binary.length; index += 1) bytes[index] = binary.charCodeAt(index);
    return bytes;
  }

  async function loadManifest() {
    const response = await fetch("./gate-manifest.json", { cache: "no-store" });
    if (!response.ok) throw new Error("encrypted payload unavailable");
    return response.json();
  }

  async function deriveKey(code, manifest) {
    const baseKey = await crypto.subtle.importKey(
      "raw",
      new TextEncoder().encode(code.trim().toUpperCase()),
      "PBKDF2",
      false,
      ["deriveKey"],
    );
    return crypto.subtle.deriveKey(
      {
        name: "PBKDF2",
        hash: "SHA-256",
        salt: fromBase64(manifest.salt),
        iterations: manifest.iterations,
      },
      baseKey,
      { name: "AES-GCM", length: 256 },
      false,
      ["decrypt"],
    );
  }

  async function messageWorker(message) {
    if (!("serviceWorker" in navigator)) throw new Error("service worker unavailable");
    await navigator.serviceWorker.register("./sw.js", { scope: "./", updateViaCache: "none" });
    const registration = await navigator.serviceWorker.ready;
    const worker = registration.active || registration.waiting || registration.installing;
    if (!worker) throw new Error("service worker unavailable");

    return new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const timeout = window.setTimeout(() => reject(new Error("service worker timeout")), 120000);
      channel.port1.onmessage = (event) => {
        window.clearTimeout(timeout);
        if (event.data?.ok) resolve(event.data);
        else reject(new Error(event.data?.error || "service worker rejected payload"));
      };
      worker.postMessage(message, [channel.port2]);
    });
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    const code = input.value.trim();
    if (!code) return;

    button.disabled = true;
    input.disabled = true;
    setStatus("正在准备音乐和总谱……");

    try {
      const manifest = await loadManifest();
      const key = await deriveKey(code, manifest);
      await messageWorker({ type: "UNLOCK_VIRTUAL_SITE", key });
      setStatus("邀请码正确，正在打开总谱……", "success");
      input.value = "";
      window.location.replace(new URL("./app.html", window.location.href));
    } catch (error) {
      console.warn("Invite gate unlock failed", error?.message || error);
      setStatus("邀请码不正确，或演示内容暂时无法加载。请向站点主人确认后重试。", "error");
      input.disabled = false;
      button.disabled = false;
      input.focus();
      input.select();
    }
  });

  // A grant belongs to this browser/device. Reopening and refreshing work even
  // when the browser has stopped and restarted its Service Worker.
  messageWorker({ type: "GET_GATE_STATUS" }).then((result) => {
    if (result.unlocked) window.location.replace(new URL("./app.html", window.location.href));
  }).catch(() => {});
})();
