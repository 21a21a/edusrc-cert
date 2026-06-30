const CACHE_TTL = 30 * 60 * 1000;
const EDUSRC = "https://src.sjtu.edu.cn/";
const SCAN_URL = "https://src.sjtu.edu.cn/gift/";
const CORE_FILES = ["content/engine.js", "content/bridge.js"];
const EXPECTED_ENGINE_VERSION = 7;
const MATCH_OPTIONS_KEY = "edusrc_match_options";

function storageKey(userId) {
  return `edusrc_scan_${userId}`;
}

async function getCachedScan(userId) {
  const key = storageKey(userId);
  const data = await chrome.storage.local.get(key);
  const cached = data[key];
  if (!cached) return null;
  if (cached.engineVersion !== EXPECTED_ENGINE_VERSION) return null;
  if (Date.now() - cached.scannedAt > CACHE_TTL) return null;
  return cached;
}

async function saveScan(userId, scan) {
  await chrome.storage.local.set({ [storageKey(userId)]: scan });
}

let progress = { text: "", percent: 0, running: false };
let bgScanPromise = null;

async function hasSessionCookie() {
  const cookie = await chrome.cookies.get({ url: EDUSRC, name: "sessionid" });
  return !!(cookie?.value);
}

async function findEdusrcTab() {
  const tabs = await chrome.tabs.query({ url: "https://src.sjtu.edu.cn/*" });
  const valid = tabs.filter((t) => t.id && t.url && !t.url.includes("/login"));
  if (!valid.length) return null;

  const [active] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (active?.id && valid.some((t) => t.id === active.id)) return active;

  return valid[0];
}

function waitForTabLoad(tabId, timeoutMs = 25000) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      chrome.tabs.onUpdated.removeListener(onUpdated);
      reject(new Error("EDUSRC 页面加载超时"));
    }, timeoutMs);

    function onUpdated(updatedId, info) {
      if (updatedId === tabId && info.status === "complete") {
        clearTimeout(timer);
        chrome.tabs.onUpdated.removeListener(onUpdated);
        resolve();
      }
    }

    chrome.tabs.get(tabId).then(
      (tab) => {
        if (tab.status === "complete") {
          clearTimeout(timer);
          resolve();
        } else {
          chrome.tabs.onUpdated.addListener(onUpdated);
        }
      },
      (err) => {
        clearTimeout(timer);
        reject(err);
      }
    );
  });
}

async function getOrCreateEdusrcTab() {
  const existing = await findEdusrcTab();
  if (existing?.id) return { tab: existing, created: false };

  if (!(await hasSessionCookie())) {
    throw new Error("NOT_LOGGED_IN");
  }

  const tab = await chrome.tabs.create({ url: SCAN_URL, active: false });
  await waitForTabLoad(tab.id);
  await new Promise((r) => setTimeout(r, 1000));
  return { tab, created: true };
}

async function ensureContentScripts(tabId, force = false) {
  for (let i = 0; i < 5; i++) {
    if (!force) {
      try {
        const pong = await chrome.tabs.sendMessage(tabId, { type: "PING" });
        if (pong?.ok && pong?.hasApi && pong?.engineVersion === EXPECTED_ENGINE_VERSION) return;
      } catch {
        /* inject and retry */
      }
    }

    await chrome.scripting.executeScript({
      target: { tabId },
      files: CORE_FILES,
    });
    await new Promise((r) => setTimeout(r, 400 + i * 300));
    force = false;
  }

  throw new Error("无法连接页面脚本，请刷新 EDUSRC 页面后重试");
}

async function sendToEdusrcTab(message) {
  const { tab, created } = await getOrCreateEdusrcTab();
  if (!tab?.id) throw new Error("无法创建 EDUSRC 扫描页");

  await ensureContentScripts(tab.id);

  let lastError;
  for (let i = 0; i < 3; i++) {
    try {
      const result = await chrome.tabs.sendMessage(tab.id, message);
      if (created) chrome.tabs.remove(tab.id).catch(() => {});
      return result;
    } catch (err) {
      lastError = err;
      await ensureContentScripts(tab.id);
    }
  }

  if (created) chrome.tabs.remove(tab.id).catch(() => {});
  throw new Error(lastError?.message || "无法连接页面脚本，请刷新 EDUSRC 页面后重试");
}

function broadcastScanDone(scan) {
  chrome.tabs.query({ url: "https://src.sjtu.edu.cn/*" }).then((tabs) => {
    tabs.forEach((tab) => {
      if (tab.id) {
        chrome.tabs.sendMessage(tab.id, { type: "SCAN_DONE", scan }).catch(() => {});
      }
    });
  });
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  if (msg.type === "SET_PROGRESS") {
    progress = msg.progress || progress;
    return false;
  }

  if (msg.type === "GET_PROGRESS") {
    sendResponse(progress);
    return false;
  }

  if (msg.type === "SAVE_SCAN") {
    saveScan(msg.scan.userId, msg.scan)
      .then(() => {
        broadcastScanDone(msg.scan);
        sendResponse({ ok: true });
      })
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "LOAD_CACHE") {
    getCachedScan(msg.userId)
      .then((scan) => sendResponse({ ok: true, scan }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "START_SCAN") {
    if (bgScanPromise) {
      bgScanPromise.then((res) => sendResponse(res)).catch((err) =>
        sendResponse({ ok: false, error: err.message })
      );
      return true;
    }

    progress = { text: "准备扫描…", percent: 0, running: true };
    bgScanPromise = sendToEdusrcTab({ type: "RUN_SCAN", matchOptions: msg.matchOptions })
      .then((res) => {
        if (!res?.ok) {
          progress = { text: res?.error || "扫描失败", percent: 0, running: false };
          return res;
        }
        progress = { text: "完成", percent: 100, running: false };
        return res;
      })
      .catch((err) => {
        progress = { text: err.message, percent: 0, running: false };
        return { ok: false, error: err.message };
      })
      .finally(() => {
        bgScanPromise = null;
      });

    bgScanPromise.then((res) => sendResponse(res));
    return true;
  }

  if (msg.type === "GET_CACHED") {
    sendToEdusrcTab({ type: "GET_SESSION" })
      .then(async (session) => {
        if (!session?.ok) {
          sendResponse(session);
          return;
        }
        const cached = await getCachedScan(session.userId);
        sendResponse({ ok: true, userId: session.userId, scan: cached });
      })
      .catch((err) =>
        sendResponse({
          ok: false,
          error: err.message === "NOT_LOGGED_IN" ? "NOT_LOGGED_IN" : err.message,
        })
      );
    return true;
  }

  if (msg.type === "GET_MATCH_OPTIONS") {
    chrome.storage.local.get(MATCH_OPTIONS_KEY).then((data) => {
      sendResponse({
        ok: true,
        options: {
          excludeFailed: true,
          includePending: false,
          ...(data[MATCH_OPTIONS_KEY] || {}),
        },
      });
    });
    return true;
  }

  if (msg.type === "SAVE_MATCH_OPTIONS") {
    chrome.storage.local
      .set({ [MATCH_OPTIONS_KEY]: msg.options })
      .then(() => sendResponse({ ok: true }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "REMATCH_SCAN") {
    sendToEdusrcTab({
      type: "REMATCH_SCAN",
      scan: msg.scan,
      matchOptions: msg.matchOptions,
    })
      .then((res) => sendResponse(res))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }

  if (msg.type === "CHECK_LOGIN") {
    hasSessionCookie().then((loggedIn) => {
      sendResponse({
        ok: true,
        loggedIn,
        error: loggedIn ? undefined : "NOT_LOGGED_IN",
      });
    });
    return true;
  }

  if (msg.type === "ENSURE_ENGINE" && _sender.tab?.id) {
    ensureContentScripts(_sender.tab.id, true)
      .then(() => sendResponse({ ok: true, engineVersion: EXPECTED_ENGINE_VERSION }))
      .catch((err) => sendResponse({ ok: false, error: err.message }));
    return true;
  }
});

chrome.runtime.onInstalled.addListener(async () => {
  const all = await chrome.storage.local.get(null);
  const keys = Object.keys(all).filter(
    (k) => k.startsWith("edusrc_scan_") || k === "edusrc_gift_catalog_v1"
  );
  if (keys.length) await chrome.storage.local.remove(keys);
});
