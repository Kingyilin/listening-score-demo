(() => {
  "use strict";

  const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
  const decoder = new TextDecoder();
  const encoder = new TextEncoder();
  const siteBase = new URL("./", window.location.href);
  const databaseName = `listening-score-gate:${siteBase.pathname}`;
  const MAX_BUNDLE_BYTES = 32 * 1024 * 1024;
  let bundlePromise;
  let bundleIdentity;
  let launchPromise;
  let activeGrant;
  let virtualFiles = new Map();
  const objectUrls = new Map();
  const mediaUrls = new Map();
  const mediaLoads = new Map();

  function gateError(code, message, cause) {
    const error = new Error(message);
    error.code = code;
    if (cause) error.cause = cause;
    return error;
  }

  function progress(onProgress, phase, loaded = 0, total = 0) {
    try { onProgress?.({ phase, loaded, total, percent: total > 0 ? Math.min(100, Math.floor(loaded / total * 100)) : 0 }); } catch { /* UI feedback cannot alter authorization. */ }
  }

  function requireCrypto() {
    if (typeof crypto === "undefined" || !crypto.subtle?.decrypt || !crypto.subtle?.digest) {
      throw gateError("UNSUPPORTED_BROWSER", "此浏览器不支持安全解锁，请在更新后的 Safari 或系统浏览器打开。");
    }
  }

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

  async function storageAttempt(operation, value) {
    let timer;
    try {
      return await Promise.race([
        storedGrant(operation, value),
        new Promise((_, reject) => { timer = setTimeout(() => reject(new Error("device storage timeout")), 5000); }),
      ]);
    } finally { clearTimeout(timer); }
  }

  async function withNetworkTimeout(milliseconds, operation, message) {
    const controller = typeof AbortController === "undefined" ? null : new AbortController();
    let expired = false;
    let timer;
    try {
      return await Promise.race([
        operation(controller?.signal, () => expired),
        new Promise((_, reject) => {
          timer = setTimeout(() => {
            expired = true;
            controller?.abort();
            reject(gateError("NETWORK", message));
          }, milliseconds);
        }),
      ]);
    } finally { clearTimeout(timer); }
  }

  async function currentManifest() {
    const url = new URL("gate-manifest.json", siteBase);
    url.searchParams.set("fresh", String(Date.now()));
    try {
      return await withNetworkTimeout(30000, async signal => {
        const response = await fetch(url, { cache: "no-store", ...(signal ? { signal } : {}) });
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        return response.json();
      }, "演示版本信息下载超时，请检查网络后重试。");
    } catch (error) {
      if (error.code) throw error;
      throw gateError("NETWORK", "暂时无法载入演示，请检查网络后重试。", error);
    }
  }

  function validateManifest(manifest) {
    try {
      if (!manifest || manifest.version !== 1 || manifest.algorithm !== "AES-256-GCM" || manifest.kdf !== "PBKDF2-SHA-256"
        || !Number.isInteger(manifest.iterations) || manifest.iterations < 10000 || manifest.iterations > 2000000
        || bytesFromBase64(manifest.salt).length !== 16 || bytesFromBase64(manifest.iv).length !== 12) throw new Error("manifest");
      if (manifest.payload && (!/^(?:audio|payload)-\d+\.bin$/.test(manifest.payload.url || "")
        || !Number.isSafeInteger(manifest.payload.length) || manifest.payload.length < 16 || manifest.payload.length > MAX_BUNDLE_BYTES
        || !/^[a-f0-9]{64}$/i.test(manifest.payload.sha256 || ""))) throw new Error("payload descriptor");
      if (manifest.inviteCheck && (bytesFromBase64(manifest.inviteCheck.iv).length !== 12
        || bytesFromBase64(manifest.inviteCheck.ciphertext).length < 16
        || bytesFromBase64(manifest.inviteCheck.ciphertext).length > 256)) throw new Error("invite check");
    } catch (error) { throw gateError("BUNDLE_INVALID", "演示版本信息无效，请刷新页面重试。", error); }
  }

  function identityFor(manifest) {
    return JSON.stringify([manifest.salt, manifest.iv, manifest.iterations, manifest.payload || null, manifest.inviteCheck || null]);
  }

  function forgetBundle(identity) {
    if (identity === bundleIdentity) { bundlePromise = null; bundleIdentity = null; }
  }

  async function verifyPayloadIntegrity(payload, descriptor) {
    if (payload.byteLength > MAX_BUNDLE_BYTES || (descriptor && payload.byteLength !== descriptor.length)) {
      throw gateError("VERSION_MISMATCH", "下载的总谱内容不完整，请重新加载。");
    }
    if (descriptor) {
      const digest = Array.from(new Uint8Array(await crypto.subtle.digest("SHA-256", payload)), byte => byte.toString(16).padStart(2, "0")).join("");
      if (digest !== descriptor.sha256.toLowerCase()) throw gateError("VERSION_MISMATCH", "总谱内容与版本不一致，请重新加载。");
    }
  }

  async function verifyInvite(key, manifest) {
    if (!validKey(key)) throw gateError("UNSUPPORTED_BROWSER", "浏览器无法创建安全密钥，请使用系统浏览器。");
    if (!manifest.inviteCheck) return false; // Old publications have no small verifier.
    let plaintext;
    try {
      plaintext = await crypto.subtle.decrypt({ name: "AES-GCM", tagLength: 128,
        iv: bytesFromBase64(manifest.inviteCheck.iv), additionalData: encoder.encode("tingjian-zongpu/static-gate/check/v1") },
      key, bytesFromBase64(manifest.inviteCheck.ciphertext));
    } catch (error) { throw gateError("BAD_INVITE", "邀请码不正确，请核对后重试。", error); }
    if (decoder.decode(plaintext) !== "TGATE-INVITE-VALID-1") throw gateError("BUNDLE_INVALID", "邀请码验证内容无效，请刷新重试。");
    return true;
  }

  async function downloadBundle(manifest, onProgress) {
    const descriptor = manifest.payload;
    const url = new URL(descriptor?.url || "payload.bin", siteBase);
    // Legacy URLs are overwritten by old publishers; explicitly bypass stale
    // intermediary caches as well as the browser cache when retrying them.
    if (!descriptor) url.searchParams.set("fresh", `${Date.now()}-${Math.random().toString(36).slice(2)}`);
    try {
      return await withNetworkTimeout(90000, async (signal, isExpired) => {
      const report = (loaded, total) => { if (!isExpired()) progress(onProgress, "download", loaded, total); };
      const response = await fetch(url, { cache: "no-store", ...(signal ? { signal } : {}) });
      if (!response.ok) throw gateError(descriptor && response.status === 404 ? "VERSION_MISMATCH" : "NETWORK", "总谱内容暂时无法下载，请重试。");
      const total = descriptor?.length || Number(response.headers?.get("content-length")) || 0;
      if (total > MAX_BUNDLE_BYTES) throw gateError("BUNDLE_INVALID", "演示内容大小异常，请联系站点主人。");
      report(0, total);
      let payload;
      if (response.body?.getReader) {
        const reader = response.body.getReader();
        const chunks = [];
        let loaded = 0;
        let lastReported = 0;
        try {
          while (true) {
            const { done, value } = await reader.read();
            if (done) break;
            loaded += value.byteLength;
            if (loaded > MAX_BUNDLE_BYTES || (descriptor && loaded > descriptor.length)) {
              await reader.cancel().catch(() => {});
              throw gateError("VERSION_MISMATCH", "下载的总谱版本不完整，正在重新获取。");
            }
            chunks.push(value);
            if (Date.now() - lastReported >= 200) { report(loaded, total); lastReported = Date.now(); }
          }
        } finally { reader.releaseLock(); }
        const bytes = new Uint8Array(loaded);
        let offset = 0;
        for (const chunk of chunks) { bytes.set(chunk, offset); offset += chunk.byteLength; }
        payload = bytes.buffer;
      } else payload = await response.arrayBuffer();
      await verifyPayloadIntegrity(payload, descriptor);
      report(payload.byteLength, total || payload.byteLength);
      return payload;
      }, "总谱下载超时，请检查网络后重试。");
    } catch (error) {
      if (error.code) throw error;
      throw gateError("NETWORK", error.name === "AbortError" ? "总谱下载超时，请检查网络后重试。" : "总谱下载中断，请检查网络后重试。", error);
    }
  }

  function officialBundle(manifest, onProgress) {
    const identity = identityFor(manifest);
    if (!bundlePromise || bundleIdentity !== identity) {
      bundleIdentity = identity;
      const pending = downloadBundle(manifest, onProgress).then(payload => ({ manifest, payload }))
        .catch(error => { if (bundlePromise === pending) forgetBundle(identity); throw error; });
      bundlePromise = pending;
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
    if (!validKey(grant.key)) throw gateError("UNSUPPORTED_BROWSER", "浏览器无法读取安全密钥，请使用系统浏览器。");
    let plaintext;
    try {
      plaintext = await crypto.subtle.decrypt({
        name: "AES-GCM", iv: bytesFromBase64(grant.manifest.iv), tagLength: 128,
        additionalData: encoder.encode("tingjian-zongpu/static-gate/v1"),
      }, grant.key, grant.payload);
    } catch (error) {
      throw gateError("VERSION_MISMATCH", "总谱内容验证失败，请重新获取当前版本。", error);
    }
    try { return unpackPayload(plaintext); }
    catch (error) { throw gateError("BUNDLE_INVALID", "演示内容无效，请联系站点主人。", error); }
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
    const previous = {
      nodes: Array.from(document.body.childNodes || []), bodyClass: document.body.className,
      title: document.title, lang: document.documentElement.lang, theme: document.getElementById("gate-theme"),
      assets: window.ListeningScoreAssets, files: virtualFiles, grant: activeGrant,
    };
    const resources = [];
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
        resources.push(stylesheet);
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
        resources.push(script);
        await appendResource(script, document.body);
      }
      window.scrollTo(0, 0);
      if (!remembered) showStorageNotice();
      return { unlocked: true, remembered };
    })().catch(error => {
      resources.forEach(resource => resource.remove());
      document.body.className = previous.bodyClass;
      document.body.replaceChildren(...previous.nodes);
      document.title = previous.title;
      document.documentElement.lang = previous.lang || "zh-CN";
      if (previous.theme && !document.getElementById("gate-theme")) document.head.append(previous.theme);
      if (previous.assets) window.ListeningScoreAssets = previous.assets;
      else delete window.ListeningScoreAssets;
      virtualFiles = previous.files;
      activeGrant = previous.grant;
      for (const url of objectUrls.values()) URL.revokeObjectURL(url);
      objectUrls.clear();
      launchPromise = null;
      throw gateError("LAUNCH_FAILED", "邀请码已验证，但浏览器未能打开总谱，请刷新或改用系统浏览器。", error);
    });
    return launchPromise;
  }

  async function unlock(key, suppliedManifest, { onProgress } = {}) {
    requireCrypto();
    const manifest = suppliedManifest || await currentManifest();
    validateManifest(manifest);
    const identity = identityFor(manifest);
    try {
      progress(onProgress, "invite", 0, 1);
      await verifyInvite(key, manifest);
      progress(onProgress, "invite", 1, 1);
      const grant = { ...await officialBundle(manifest, onProgress), key, expiresAt: Date.now() + SESSION_MS };
      progress(onProgress, "decrypt", 0, 1);
      const files = await decryptFiles(grant);
      progress(onProgress, "decrypt", 1, 1);
      let remembered = true;
      try { await storageAttempt("put", grant); } catch { remembered = false; }
      progress(onProgress, "launch", 0, 1);
      const result = await launch(files, grant, remembered);
      progress(onProgress, "launch", 1, 1);
      return result;
    } catch (error) {
      // An authenticated transport response can still be an old/partial bundle.
      // Never pin that failed response across another press of the unlock key.
      forgetBundle(identity);
      throw error;
    }
  }

  async function resume() {
    let grant;
    try { grant = await storageAttempt("get"); } catch { return { unlocked: false }; }
    if (!grant || !Number.isFinite(grant.expiresAt) || grant.expiresAt <= Date.now()) return { unlocked: false };
    try {
      const manifest = await currentManifest();
      validateManifest(manifest);
      if (manifest.salt !== grant.manifest?.salt || manifest.iv !== grant.manifest?.iv || manifest.iterations !== grant.manifest?.iterations) {
        await storageAttempt("delete");
        return { unlocked: false };
      }
      // A compatibility hotfix may add proof/integrity metadata without changing
      // the encrypted content. Authenticate the retained bytes against that new
      // descriptor, then keep the original grant expiry instead of asking again.
      requireCrypto();
      await verifyInvite(grant.key, manifest);
      await verifyPayloadIntegrity(grant.payload, manifest.payload);
      const resumedGrant = { ...grant, manifest };
      return launch(await decryptFiles(resumedGrant), resumedGrant, true);
    } catch {
      await storageAttempt("delete").catch(() => {});
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
  const visibilityToggle = document.querySelector("#toggle-invite-code");
  const progress = document.querySelector("#gate-progress");
  const inputNote = document.querySelector("#invite-format-note");
  const portablePreferred = /MicroMessenger/i.test(navigator.userAgent || "")
    || new URL(window.location.href).searchParams.get("mode") !== "worker"
    || !("serviceWorker" in navigator);
  const messages = {
    BAD_INVITE: "邀请码不正确。请点“显示”核对，或向站点主人索取；多余空格和连接号格式已自动清理。",
    NETWORK: "网络连接失败，演示内容尚未下载完成；不是邀请码错误。请切换网络或稍后重试。",
    VERSION_MISMATCH: "网站刚更新，当前内容版本未对上。请刷新此页后重试，无需更换邀请码。",
    UNSUPPORTED_BROWSER: "此浏览器暂不支持安全解锁。请在右上角菜单选择 Safari 或系统浏览器打开。",
    BUNDLE_INVALID: "演示内容校验失败，无法安全打开。请刷新后重试；这不代表邀请码错误。",
    LAUNCH_FAILED: "页面载入失败，尚未成功打开。请刷新后重试，或使用系统浏览器；这不代表邀请码错误。",
  };
  let submitting = false;

  function gateError(code, cause) {
    const error = new Error(messages[code] || messages.LAUNCH_FAILED);
    error.code = code;
    if (cause) error.cause = cause;
    return error;
  }

  // Keep this canonicalization identical to scripts/static-gate-core.mjs.
  function normalizeInviteCode(value) {
    return String(value || "").normalize("NFKC")
      .replace(/[\u2010-\u2015\u2212\uFE58\uFE63\uFF0D]/g, "-")
      .replace(/[\s\u00AD\u061C\u180E\u200B-\u200F\u202A-\u202E\u2060-\u206F\uFEFF]/g, "")
      .toUpperCase();
  }

  function normalizeInput() {
    const original = input.value;
    const normalized = normalizeInviteCode(original);
    if (normalized !== original) {
      const caret = Number.isInteger(input.selectionStart) ? normalizeInviteCode(original.slice(0, input.selectionStart)).length : normalized.length;
      input.value = normalized;
      input.setSelectionRange?.(caret, caret);
      if (inputNote) inputNote.textContent = "已自动清理空格、隐藏字符和连接号格式。可以点“显示”核对。";
    }
    return normalized;
  }

  input.addEventListener?.("blur", normalizeInput);
  input.addEventListener?.("input", (event) => { if (!event.isComposing) normalizeInput(); });
  input.addEventListener?.("compositionend", normalizeInput);
  input.addEventListener?.("paste", (event) => {
    const text = event.clipboardData?.getData("text/plain") || event.clipboardData?.getData("text");
    // Some iPhone WebViews do not expose clipboard text to script. Let the
    // system paste normally; the subsequent input event cleans up its value.
    if (typeof text !== "string" || !text) return;
    event.preventDefault();
    const start = Number.isInteger(input.selectionStart) ? input.selectionStart : 0;
    const end = Number.isInteger(input.selectionEnd) ? input.selectionEnd : input.value.length;
    input.value = input.value.slice(0, start) + text + input.value.slice(end);
    normalizeInput();
    input.setSelectionRange?.(input.value.length, input.value.length);
  });
  visibilityToggle?.addEventListener("click", () => {
    const visible = input.type === "password";
    input.type = visible ? "text" : "password";
    visibilityToggle.textContent = visible ? "隐藏" : "显示";
    visibilityToggle.setAttribute("aria-label", visible ? "隐藏邀请码" : "显示邀请码");
    visibilityToggle.setAttribute("aria-pressed", String(visible));
  });

  function setStatus(message, kind = "", code = "") {
    status.textContent = message;
    status.className = `status ${kind}`.trim();
    if (status.dataset) status.dataset.errorCode = code;
  }

  function showProgress(value = {}) {
    const phase = value.phase || "invite";
    if (progress) {
      progress.hidden = false;
      if (phase === "download" && Number(value.total) > 0) {
        progress.value = Math.max(0, Math.min(100, Number(value.percent) || Number(value.loaded) / Number(value.total) * 100));
      } else progress.removeAttribute?.("value");
    }
    if (phase === "download") {
      const loaded = (Math.max(0, Number(value.loaded) || 0) / 1_000_000).toFixed(1);
      const total = Number(value.total) > 0 ? ` / ${(Number(value.total) / 1_000_000).toFixed(1)} MB` : " MB";
      setStatus(`正在下载演示内容：${loaded}${total}。请保持页面打开……`);
    } else if (phase === "decrypt") setStatus("正在校验并解密总谱……");
    else if (phase === "launch") setStatus("正在打开总谱……");
    else setStatus("正在验证邀请码……");
  }

  function withTimeout(promise, milliseconds = 8000) {
    let timer;
    return Promise.race([
      promise,
      new Promise((_, reject) => { timer = setTimeout(() => reject(gateError("NETWORK")), milliseconds); }),
    ]).finally(() => clearTimeout(timer));
  }

  function portableRuntime() {
    if (!window.ListeningScorePortable) throw gateError("UNSUPPORTED_BROWSER");
    return window.ListeningScorePortable;
  }

  function fromBase64(value) {
    const binary = atob(value);
    return Uint8Array.from(binary, (character) => character.charCodeAt(0));
  }

  async function loadManifest(refresh = false) {
    const url = new URL("./gate-manifest.json", window.location.href);
    if (refresh) url.searchParams.set("refresh", String(Date.now()));
    let response;
    try { response = await withTimeout(fetch(url, { cache: "no-store" }), 20000); }
    catch (error) { throw gateError("NETWORK", error); }
    if (!response.ok) throw gateError("NETWORK");
    try {
      const manifest = await response.json();
      if (manifest.version !== 1 || manifest.algorithm !== "AES-256-GCM" || manifest.kdf !== "PBKDF2-SHA-256"
        || !Number.isInteger(manifest.iterations) || manifest.iterations < 10000 || manifest.iterations > 2000000
        || fromBase64(manifest.salt).length !== 16 || fromBase64(manifest.iv).length !== 12) throw new Error("invalid manifest");
      return manifest;
    } catch (error) { throw gateError("BUNDLE_INVALID", error); }
  }

  async function deriveKey(code, manifest) {
    if (typeof crypto === "undefined" || !crypto.subtle || typeof TextEncoder === "undefined"
      || window.isSecureContext === false) throw gateError("UNSUPPORTED_BROWSER");
    try {
      const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(code), "PBKDF2", false, ["deriveKey"]);
      return await crypto.subtle.deriveKey({ name: "PBKDF2", hash: "SHA-256", salt: fromBase64(manifest.salt), iterations: manifest.iterations },
        baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
    } catch (error) { throw gateError("UNSUPPORTED_BROWSER", error); }
  }

  async function messageWorker(message) {
    if (!("serviceWorker" in navigator)) throw gateError("UNSUPPORTED_BROWSER");
    await withTimeout(navigator.serviceWorker.register("./sw.js", { scope: "./", updateViaCache: "none" }));
    const registration = await withTimeout(navigator.serviceWorker.ready);
    const worker = registration.active || registration.waiting || registration.installing;
    if (!worker) throw gateError("UNSUPPORTED_BROWSER");
    return new Promise((resolve, reject) => {
      const channel = new MessageChannel();
      const timeout = window.setTimeout(() => reject(gateError("NETWORK")), 120000);
      channel.port1.onmessage = (event) => {
        window.clearTimeout(timeout);
        if (event.data?.ok) resolve(event.data);
        else reject(gateError(messages[event.data?.code] ? event.data.code : "BUNDLE_INVALID"));
      };
      worker.postMessage(message, [channel.port2]);
    });
  }

  async function unlock(code, refresh = false) {
    const manifest = await loadManifest(refresh);
    const key = await deriveKey(code, manifest);
    if (!portablePreferred) {
      try {
        await messageWorker({ type: "UNLOCK_VIRTUAL_SITE", key, manifest });
        setStatus("正在打开总谱……", "success");
        input.value = "";
        window.location.replace(new URL("./app.html", window.location.href));
        return;
      } catch (error) {
        // Older Workers do not report typed errors. Portable verification of
        // this exact manifest distinguishes a bad invite from a stale package.
        if (["BAD_INVITE", "VERSION_MISMATCH"].includes(error.code)) throw error;
      }
    }
    await portableRuntime().unlock(key, manifest, { onProgress: showProgress });
    input.value = "";
  }

  form.addEventListener("submit", async (event) => {
    event.preventDefault();
    if (submitting) return;
    const code = normalizeInput();
    if (!code) { setStatus("请先输入站点主人提供的邀请码。", "error", "BAD_INVITE"); return; }
    submitting = true;
    button.disabled = true;
    input.disabled = true;
    if (visibilityToggle) visibilityToggle.disabled = true;
    showProgress({ phase: "invite" });
    try {
      try { await unlock(code); }
      catch (error) {
        if (error.code !== "VERSION_MISMATCH") throw error;
        setStatus("网站刚更新，正在重新同步版本……");
        await unlock(code, true);
      }
    } catch (error) {
      const code = messages[error?.code] ? error.code : "LAUNCH_FAILED";
      console.warn("Invite gate unlock failed", code, error?.name || "Error");
      setStatus(`${messages[code]}（${code}）`, "error", code);
      input.disabled = false;
      button.disabled = false;
      if (visibilityToggle) visibilityToggle.disabled = false;
      if (progress) progress.hidden = true;
      input.focus();
      input.select();
    } finally { submitting = false; }
  });

  if (portablePreferred) {
    Promise.resolve().then(() => portableRuntime().resume()).catch(() => {});
  } else {
    messageWorker({ type: "GET_GATE_STATUS" }).then((result) => {
      if (result.unlocked) window.location.replace(new URL("./app.html", window.location.href));
    }).catch(() => Promise.resolve().then(() => portableRuntime().resume()).catch(() => {}));
  }
})();
