(function (g) {
  if (g.__EDUSRC_BRIDGE__) return;
  g.__EDUSRC_BRIDGE__ = true;

  let scanPromise = null;

  function reportProgress(p) {
    chrome.runtime.sendMessage({ type: "SET_PROGRESS", progress: p }).catch(() => {});
  }

  async function doScan(matchOptions) {
    const api = g.EdusrcApi;
    if (!api) throw new Error("核心模块未加载，请刷新页面");

    reportProgress({ text: "开始扫描…", percent: 0, running: true });
    const scan = await api.runScan((p) => reportProgress(p), matchOptions);
    await chrome.runtime.sendMessage({ type: "SAVE_SCAN", scan });
    reportProgress({ text: "完成", percent: 100, running: false });
    return scan;
  }

  chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
    if (msg.type === "PING") {
      sendResponse({ ok: true, hasApi: !!g.EdusrcApi, engineVersion: g.__EDUSRC_ENGINE_V__ || 0 });
      return false;
    }

    if (msg.type === "RUN_SCAN") {
      if (!scanPromise) {
        scanPromise = doScan(msg.matchOptions).finally(() => {
          scanPromise = null;
        });
      }
      scanPromise
        .then((scan) => sendResponse({ ok: true, scan }))
        .catch((err) =>
          sendResponse({
            ok: false,
            error: err.message === "NOT_LOGGED_IN" ? "NOT_LOGGED_IN" : err.message,
          })
        );
      return true;
    }

    if (msg.type === "REMATCH_SCAN") {
      (async () => {
        try {
          const api = g.EdusrcApi;
          if (!api?.rematchScan) {
            sendResponse({ ok: false, error: "模块未加载" });
            return;
          }
          const scan = api.rematchScan(msg.scan, msg.matchOptions);
          await chrome.runtime.sendMessage({ type: "SAVE_SCAN", scan });
          sendResponse({ ok: true, scan });
        } catch (err) {
          sendResponse({ ok: false, error: err.message });
        }
      })();
      return true;
    }
      (async () => {
        try {
          const parser = g.EdusrcParser;
          const api = g.EdusrcApi;
          if (!parser || !api) {
            sendResponse({ ok: false, error: "模块未加载，请刷新页面" });
            return;
          }
          const session = await parser.detectSession(api.fetchPage);
          if (!session.loggedIn) {
            sendResponse({ ok: false, error: "NOT_LOGGED_IN" });
            return;
          }
          sendResponse({ ok: true, loggedIn: true, userId: session.userId || "self" });
        } catch (err) {
          sendResponse({ ok: false, error: err.message });
        }
      })();
      return true;
    }
  });
})(globalThis);
