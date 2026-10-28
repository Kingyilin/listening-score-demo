"use strict";

const SESSION_MS = 7 * 24 * 60 * 60 * 1000;
const AAD = new TextEncoder().encode("tingjian-zongpu/static-gate/v1");
const decoder = new TextDecoder();
const scopePath = new URL(self.registration.scope).pathname;
const databaseName = `listening-score-gate:${scopePath}`;
let virtualFiles = new Map();
let expiresAt = 0;
let restorePromise;
let bundlePromise;
let deviceKey;
const mediaCache = new Map();
const mediaLoads = new Map();

function openDatabase() {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(databaseName, 1);
    request.onupgradeneeded = () => request.result.createObjectStore("grants");
    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
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
      transaction.onabort = () => reject(transaction.error || new Error("storage aborted"));
    });
  } finally {
    database.close();
  }
}

function fromBase64(value) {
  return Uint8Array.from(atob(value), (character) => character.charCodeAt(0));
}

function validKey(key) {
  return key instanceof CryptoKey && key.type === "secret" && !key.extractable
    && key.algorithm?.name === "AES-GCM" && key.usages.includes("decrypt");
}

async function decryptFiles(grant) {
  if (!validKey(grant.key)) throw new Error("invalid device key");
  const plaintext = await crypto.subtle.decrypt({
    name: "AES-GCM",
    iv: fromBase64(grant.manifest.iv),
    additionalData: AAD,
    tagLength: 128,
  }, grant.key, grant.payload);
  const bytes = new Uint8Array(plaintext);
  if (decoder.decode(bytes.subarray(0, 8)) !== "TGATE001") throw new Error("invalid payload");
  const headerLength = new DataView(plaintext).getUint32(8, false);
  const dataStart = 12 + headerLength;
  if (dataStart > bytes.length) throw new Error("invalid header");
  const header = JSON.parse(decoder.decode(bytes.subarray(12, dataStart)));
  const files = new Map();
  for (const file of header.files) {
    const start = dataStart + file.offset;
    const end = start + file.length;
    if (!file.path || file.path.startsWith("/") || file.path.split("/").includes("..")
      || !Number.isInteger(file.offset) || !Number.isInteger(file.length)
      || start < dataStart || end < start || end > bytes.length) throw new Error("invalid file");
    files.set(file.path, { data: bytes.slice(start, end).buffer, mime: file.mime });
  }
  if (!files.has("app.html")) throw new Error("application entry is missing");
  return files;
}

async function ensureVirtualSite() {
  if (expiresAt > Date.now() && virtualFiles.size) return true;
  virtualFiles.clear();
  expiresAt = 0;
  deviceKey = undefined;
  mediaCache.clear();
  if (!restorePromise) {
    restorePromise = (async () => {
      const grant = await storedGrant("get");
      if (!grant || !Number.isFinite(grant.expiresAt) || grant.expiresAt <= Date.now()) {
        if (grant) await storedGrant("delete");
        return false;
      }
      try {
        // A new publication rotates the payload's salt/IV. Ask for the invite
        // again instead of mixing a saved application with newly encrypted media.
        const response = await fetch(new URL("gate-manifest.json", self.registration.scope), { cache: "no-store" });
        if (!response.ok) throw new Error("current publication unavailable");
        const current = await response.json();
        if (current.salt !== grant.manifest?.salt || current.iv !== grant.manifest?.iv) {
          await storedGrant("delete");
          return false;
        }
        virtualFiles = await decryptFiles(grant);
        expiresAt = grant.expiresAt;
        deviceKey = grant.key;
        return true;
      } catch {
        await storedGrant("delete");
        return false;
      }
    })().finally(() => { restorePromise = null; });
  }
  return restorePromise;
}

function mediaDescriptor(relativePath) {
  const file = virtualFiles.get("__gate_media.json");
  if (!file) return null;
  return JSON.parse(decoder.decode(file.data)).files?.[relativePath] || null;
}

async function loadMedia(relativePath, descriptor) {
  if (mediaCache.has(relativePath)) {
    const entry = mediaCache.get(relativePath);
    mediaCache.delete(relativePath);
    mediaCache.set(relativePath, entry);
    return entry;
  }
  if (!mediaLoads.has(relativePath)) {
    const key = deviceKey;
    mediaLoads.set(relativePath, (async () => {
      const response = await fetch(new URL(descriptor.url, self.registration.scope));
      if (!response.ok) throw new Error("audio unavailable");
      const data = await crypto.subtle.decrypt({
        name: "AES-GCM", iv: fromBase64(descriptor.iv), tagLength: 128,
        additionalData: new TextEncoder().encode(`tingjian-zongpu/static-gate/media/v1:${relativePath}`),
      }, key, await response.arrayBuffer());
      if (data.byteLength !== descriptor.length) throw new Error("invalid audio length");
      const file = { data, mime: descriptor.mime };
      if (expiresAt > Date.now() && deviceKey === key) {
        mediaCache.set(relativePath, file);
        while (mediaCache.size > 2) mediaCache.delete(mediaCache.keys().next().value);
      }
      return file;
    })().finally(() => { mediaLoads.delete(relativePath); }));
  }
  return mediaLoads.get(relativePath);
}

function mediaResponse(request, file) {
  const length = file.data.byteLength;
  const headers = {
    "content-type": file.mime || "audio/ogg", "accept-ranges": "bytes",
    "cache-control": "private, no-store", "x-content-type-options": "nosniff",
  };
  const range = request.headers.get("range");
  if (!range) return new Response(request.method === "HEAD" ? null : file.data.slice(0), {
    status: 200, headers: { ...headers, "content-length": String(length) },
  });
  const match = /^bytes=(\d*)-(\d*)$/.exec(range);
  let start = match?.[1] ? Number(match[1]) : 0;
  let end = match?.[2] ? Number(match[2]) : length - 1;
  if (match && !match[1] && match[2]) {
    start = Math.max(0, length - Number(match[2]));
    end = length - 1;
  }
  end = Math.min(end, length - 1);
  if (!match || (!match[1] && !match[2]) || !Number.isSafeInteger(start) || !Number.isSafeInteger(end)
    || start < 0 || start >= length || end < start) return new Response(null, {
    status: 416, headers: { ...headers, "content-range": `bytes */${length}` },
  });
  return new Response(request.method === "HEAD" ? null : file.data.slice(start, end + 1), {
    status: 206,
    headers: { ...headers, "content-range": `bytes ${start}-${end}/${length}`, "content-length": String(end - start + 1) },
  });
}

function officialBundle() {
  // Never accept caller-supplied files or ciphertext as proof of an invite.
  // The key has to decrypt the bundle published by the site owner.
  if (!bundlePromise) {
    bundlePromise = Promise.all([
      fetch(new URL("gate-manifest.json", self.registration.scope), { cache: "no-store" }),
      fetch(new URL("payload.bin", self.registration.scope), { cache: "no-store" }),
    ]).then(async ([manifestResponse, payloadResponse]) => {
      if (!manifestResponse.ok || !payloadResponse.ok) throw new Error("演示包下载失败，请稍后重试。");
      return { manifest: await manifestResponse.json(), payload: await payloadResponse.arrayBuffer() };
    }).catch((error) => { bundlePromise = null; throw error; });
  }
  return bundlePromise;
}

self.addEventListener("install", () => self.skipWaiting());
self.addEventListener("activate", (event) => event.waitUntil(self.clients.claim()));

self.addEventListener("message", (event) => {
  if (!event.source?.url?.startsWith(self.registration.scope)) return;
  if (!["UNLOCK_VIRTUAL_SITE", "GET_GATE_STATUS", "LOCK_VIRTUAL_SITE"].includes(event.data?.type)) return;
  event.waitUntil((async () => {
    const port = event.ports[0];
    try {
      if (event.data.type === "LOCK_VIRTUAL_SITE") {
        await storedGrant("delete");
        virtualFiles.clear();
        expiresAt = 0;
        deviceKey = undefined;
        mediaCache.clear();
        port?.postMessage({ ok: true, unlocked: false });
        return;
      }
      if (event.data.type === "GET_GATE_STATUS") {
        port?.postMessage({ ok: true, unlocked: await ensureVirtualSite() });
        return;
      }
      if (!validKey(event.data.key)) throw new Error("邀请码验证失败。");
      const grant = { ...await officialBundle(), key: event.data.key, expiresAt: Date.now() + SESSION_MS };
      const files = await decryptFiles(grant);
      // Structured clone preserves a non-exportable CryptoKey in IndexedDB;
      // neither the invite code nor the decrypted application is persisted.
      await storedGrant("put", grant);
      virtualFiles = files;
      expiresAt = grant.expiresAt;
      deviceKey = grant.key;
      mediaCache.clear();
      port?.postMessage({ ok: true, unlocked: true });
    } catch (error) {
      port?.postMessage({ ok: false, error: error?.name === "OperationError" ? "邀请码不正确。" : error?.message || "解锁失败。" });
    }
  })());
});

self.addEventListener("fetch", (event) => {
  const url = new URL(event.request.url);
  if (url.origin !== self.location.origin || !url.pathname.startsWith(scopePath)) return;

  const relativePath = decodeURIComponent(url.pathname.slice(scopePath.length));
  const publicFiles = ["", "index.html", "gate.js", "sw.js", "gate-manifest.json", "payload.bin", "favicon.ico"];
  if (publicFiles.includes(relativePath) || /^audio-\d+\.bin$/.test(relativePath)) return;
  event.respondWith((async () => {
    if (await ensureVirtualSite()) {
      const media = mediaDescriptor(relativePath);
      if (media) {
        try { return mediaResponse(event.request, await loadMedia(relativePath, media)); }
        catch { return new Response("录音暂时无法加载，请重试。", { status: 503 }); }
      }
      const file = virtualFiles.get(relativePath);
      if (file) return new Response(event.request.method === "HEAD" ? null : file.data.slice(0), {
        status: 200,
        headers: {
          "content-type": file.mime || "application/octet-stream",
          "cache-control": "private, no-store",
          "x-content-type-options": "nosniff",
        },
      });
    }
    if (event.request.mode === "navigate" || relativePath === "app.html") {
      return Response.redirect(self.registration.scope, 302);
    }
    return new Response("请先输入邀请码。", { status: 401, headers: { "cache-control": "no-store" } });
  })());
});
