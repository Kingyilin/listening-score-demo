(() => {
  "use strict";

  const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const siteBase = new URL("./", window.location.href);
  const databaseName = `listening-score-gate:${siteBase.pathname}`;
  let bundlePromise;
  let launchPromise;
  let activeGrant;
  let virtualFiles = new Map();
  const objectUrls = new Map();
  const mediaUrls = new Map();
  const mediaLoads = new Map();

  function bytesFromBase64(value) {
    return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
  }

  function validKey(key) {
    return key && key.type === "secret" && key.extractable === false
      && key.algorithm?.name === "AES-GCM" && key.usages?.includes("decrypt");
  }

  function openDatabase() {
    return new Promise((resolve, reject) => {
      const request = indexedDB.open(databaseName, 1);
      request.onupgradeneeded = () => request.result.createObjectStore("grants");
      request.onsuccess = () => resolve(request.result);
      request.onerror = () => reject(request.error);
      request.onblocked = () => reject(new Error("device storage blocked"));
    });
  }

  async function storedGrant(operation, value) {
    const database = await openDatabase();
    try {
      return await new Promise((resolve, reject) => {
        const transaction = database.transaction("grants", operation === "get" ? "readonly" : "readwrite");
        const store = transaction.objectStore("grants");
        const request = operation === "get" ? store.get("active")
          : operation === "put" ? store.put(value, "active") : store.delete("active");
        let result;
        request.onsuccess = () => { result = request.result; };
        transaction.oncomplete = () => resolve(result);
        transaction.onerror = () => reject(transaction.error);
        transaction.onabort = () => reject(transaction.error || new Error("device storage aborted"));
      });
    } finally {
      database.close();
    }
  }

  async function currentManifest() {
    const response = await fetch(new URL("gate-manifest.json", siteBase), { cache: "no-store" });
    if (!response.ok) throw new Error("暂时无法载入演示，请检查网络后重试。");
    return response.json();
  }

  function officialBundle() {
    if (!bundlePromise) {
      bundlePromise = Promise.all([
        currentManifest(),
        fetch(new URL("payload.bin", siteBase), { cache: "no-store" }),
      ]).then(async ([manifest, response]) => {
        if (!response.ok) throw new Error("演示内容下载失败，请稍后重试。");
        return { manifest, payload: await response.arrayBuffer() };
      }).catch((error) => { bundlePromise = null; throw error; });
    }
    return bundlePromise;
  }

  function unpackPayload(payload) {
    const bytes = new Uint8Array(payload);
    if (bytes.length < 12 || decoder.decode(bytes.subarray(0, 8)) !== "TGATE001") throw new Error("演示内容无效。");
    const headerLength = new DataView(payload).getUint32(8, false);
    const dataStart = 12 + headerLength;
    if (dataStart > bytes.length) throw new Error("演示内容无效。");
    const header = JSON.parse(decoder.decode(bytes.subarray(12, dataStart)));
    const files = new Map();
    for (const file of header.files || []) {
      const start = dataStart + file.offset;
      const end = start + file.length;
      if (!file.path || file.path.startsWith("/") || file.path.split("/").includes("..")
        || !Number.isInteger(file.offset) || !Number.isInteger(file.length)
        || start < dataStart || end < start || end > bytes.length) throw new Error("演示内容无效。");
      files.set(file.path, { data: bytes.slice(start, end).buffer, mime: file.mime });
    }
    if (!files.has("app.html")) throw new Error("缺少演示页面。");
    return files;
  }

  async function decryptFiles(grant) {
    if (!validKey(grant.key)) throw new Error("邀请码验证失败。");
    const plaintext = await crypto.subtle.decrypt({
      name: "AES-GCM", iv: bytesFromBase64(grant.manifest.iv), tagLength: 128,
      additionalData: encoder.encode("tingjian-zongpu/static-gate/v1"),
    }, grant.key, grant.payload);
    return unpackPayload(plaintext);
  }

  function virtualPath(value) {
    if (typeof value !== "string" || !value || /^(blob:|data:)/i.test(value)) return null;
    try {
      const url = new URL(value, siteBase);
      if (url.origin !== siteBase.origin || !url.pathname.startsWith(siteBase.pathname)) return null;
      return decodeURIComponent(url.pathname.slice(siteBase.pathname.length));
    } catch { return null; }
  }

  function resolve(value) {
    const path = virtualPath(value);
    const file = path && virtualFiles.get(path);
    if (!file) return value;
    if (!objectUrls.has(path)) objectUrls.set(path, URL.createObjectURL(new Blob([file.data], { type: file.mime || "application/octet-stream" })));
    return objectUrls.get(path);
  }

  function trimMediaCache() {
    const inUse = new Set(Array.from(document.querySelectorAll?.("audio, video") || [], (element) => [
      element.currentSrc?.replace(/#.*$/, ""), element.src?.replace(/#.*$/, ""),
    ]).flat().filter(Boolean));
    for (const [path, url] of mediaUrls) {
      if (mediaUrls.size <= 2) break;
      // A superseded download may finish after the newest track has started.
      // Never revoke the URL still attached to the actual media element.
      if (inUse.has(url)) continue;
      URL.revokeObjectURL(url);
      mediaUrls.delete(path);
    }
  }

  async function resolveAudio(value) {
    const path = virtualPath(value);
    const manifestFile = virtualFiles.get("__gate_media.json");
    const descriptor = path && manifestFile && JSON.parse(decoder.decode(manifestFile.data)).files?.[path];
    if (!descriptor) return value;
    if (!activeGrant || activeGrant.expiresAt <= Date.now()) throw new Error("访问已到期，请刷新并重新输入邀请码。");
    if (mediaUrls.has(path)) {
      const url = mediaUrls.get(path);
      mediaUrls.delete(path);
      mediaUrls.set(path, url);
      return url;
    }
    if (!mediaLoads.has(path)) {
      mediaLoads.set(path, (async () => {
        const response = await fetch(new URL(descriptor.url, siteBase));
        if (!response.ok) throw new Error("录音下载失败，请稍后重试。");
        const data = await crypto.subtle.decrypt({
          name: "AES-GCM", iv: bytesFromBase64(descriptor.iv), tagLength: 128,
          additionalData: encoder.encode(`tingjian-zongpu/static-gate/media/v1:${path}`),
        }, activeGrant.key, await response.arrayBuffer());
        if (data.byteLength !== descriptor.length) throw new Error("录音内容不完整，请重试。");
        const url = URL.createObjectURL(new Blob([data], { type: descriptor.mime || "audio/mp4" }));
        mediaUrls.set(path, url);
        trimMediaCache();
        return url;
      })().finally(() => mediaLoads.delete(path)));
    }
    return mediaLoads.get(path);
  }

  function appendResource(element, target) {
    return new Promise((resolveLoad, reject) => {
      const timeout = setTimeout(() => reject(new Error("页面载入超时，请刷新重试。")), 20000);
      element.onload = () => { clearTimeout(timeout); resolveLoad(); };
      element.onerror = () => { clearTimeout(timeout); reject(new Error("页面载入失败，请刷新重试。")); };
      target.append(element);
    });
  }

  function showStorageNotice() {
    const note = document.createElement("div");
    note.setAttribute("role", "status");
    note.textContent = "本次可以正常使用；此浏览器无法记住访问状态，下次打开需要重新输入邀请码。";
    Object.assign(note.style, {
      position: "fixed", zIndex: "2000", top: "12px", left: "12px", right: "12px",
      padding: "12px 16px", borderRadius: "10px", background: "#322a1e", color: "#f5ead6",
      font: "14px/1.5 system-ui, sans-serif", boxShadow: "0 8px 30px #0006",
    });
    document.body.append(note);
    setTimeout(() => note.remove(), 9000);
  }

  function launch(files, grant, remembered) {
    if (launchPromise) return launchPromise;
    launchPromise = (async () => {
      virtualFiles = files;
      activeGrant = grant;
      window.ListeningScoreAssets = Object.freeze({ resolve, resolveAudio, mode: "portable" });
      const app = new DOMParser().parseFromString(decoder.decode(files.get("app.html").data), "text/html");
      const scripts = Array.from(app.querySelectorAll("script[src]"), (script) => script.getAttribute("src"));
      app.querySelectorAll("script").forEach((script) => script.remove());
      for (const original of app.head.querySelectorAll('link[rel="stylesheet"]')) {
        const stylesheet = document.createElement("link");
        stylesheet.rel = "stylesheet";
        stylesheet.href = resolve(original.getAttribute("href"));
        await appendResource(stylesheet, document.head);
      }
      document.getElementById("gate-theme")?.remove();
      document.title = app.title;
      document.documentElement.lang = app.documentElement.lang || "zh-CN";
      document.body.className = app.body.className;
      document.body.replaceChildren(...Array.from(app.body.childNodes, (node) => document.importNode(node, true)));
      for (const source of scripts) {
        const script = document.createElement("script");
        script.async = false;
        script.src = resolve(source);
        await appendResource(script, document.body);
      }
      window.scrollTo(0, 0);
      if (!remembered) showStorageNotice();
      return { unlocked: true, remembered };
    })();
    return launchPromise;
  }

  async function unlock(key) {
    const grant = { ...await officialBundle(), key, expiresAt: Date.now() + SESSION_MS };
    const files = await decryptFiles(grant);
    let remembered = true;
    try { await storedGrant("put", grant); } catch { remembered = false; }
    return launch(files, grant, remembered);
  }

  async function resume() {
    let grant;
    try { grant = await storedGrant("get"); } catch { return { unlocked: false }; }
    if (!grant || !Number.isFinite(grant.expiresAt) || grant.expiresAt <= Date.now()) return { unlocked: false };
    try {
      const manifest = await currentManifest();
      if (manifest.salt !== grant.manifest?.salt || manifest.iv !== grant.manifest?.iv) {
        await storedGrant("delete");
        return { unlocked: false };
      }
      return launch(await decryptFiles(grant), grant, true);
    } catch {
      await storedGrant("delete").catch(() => {});
      return { unlocked: false };
    }
  }

  window.ListeningScorePortable = Object.freeze({ unlock, resume });
})();

(() => {
  "use strict";

  const form = document.querySelector("#gate-form");
  const input = document.querySelector("#invite-code");
  const button = document.querySelector("#unlock-button");
  const status = document.querySelector("#gate-status");
  const portablePreferred = /MicroMessenger/i.test(navigator.userAgent || "")
    || new URL(window.location.href).searchParams.get("mode") !== "worker"
    || !("serviceWorker" in navigator);

  function withTimeout(promise, milliseconds = 8000) {
    let timer;
    return Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("browser access unavailable")), milliseconds); }),
    ]).finally(() => clearTimeout(timer));
  }

  function portableRuntime() {
    // The publisher prepends the portable runtime to this same public gate.js
    // file, so even an older Worker can deliver it without another route.
    if (!window.ListeningScorePortable) throw new Error("此浏览器暂时无法打开演示，请使用系统浏览器。");
    return window.ListeningScorePortable;
  }

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
    await withTimeout(navigator.serviceWorker.register("./sw.js", { scope: "./", updateViaCache: "none" }));
    const registration = await withTimeout(navigator.serviceWorker.ready);
    const worker = registration.active || registration.waiting || registration.installing;
    if (!worker) throw new Error("service worker unavailable");

    return new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const timeout = window.setTimeout(() => reject(new Error("service worker timeout")), 120000);
      channel.port1.onmessage = (event) => {
        window.clearTimeout(timeout);
        if (event.data?.ok) resolve(event.data);
        else {
          const error = new Error(event.data?.error || "service worker rejected payload");
          if (/邀请码不正确/.test(error.message)) error.code = "BAD_INVITE";
          reject(error);
        }
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
      if (portablePreferred) {
        await (await portableRuntime()).unlock(key);
        return;
      }
      try {
        await messageWorker({ type: "UNLOCK_VIRTUAL_SITE", key });
      } catch (error) {
        if (error.code === "BAD_INVITE") throw error;
        await (await portableRuntime()).unlock(key);
        return;
      }
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
  if (portablePreferred) {
    Promise.resolve().then(() => portableRuntime().resume()).catch(() => {});
  } else {
    messageWorker({ type: "GET_GATE_STATUS" }).then((result) => {
      if (result.unlocked) window.location.replace(new URL("./app.html", window.location.href));
    }).catch(() => Promise.resolve().then(() => portableRuntime().resume()).catch(() => {}));
  }
})();
