(function () {
  if (window.__edusrcCertBadge) return;
  window.__edusrcCertBadge = true;

  const isGiftPage = location.pathname.startsWith("/gift");
  const isLoginPage = location.pathname.startsWith("/login");
  let lastScan = null;

  async function loadMatchOptions() {
    const res = await send({ type: "GET_MATCH_OPTIONS" });
    return res?.options || { excludeFailed: true, includePending: false };
  }

  async function saveMatchOptions(options) {
    await send({ type: "SAVE_MATCH_OPTIONS", options });
  }

  function readMatchOptionsFromUI() {
    return {
      excludeFailed: !!document.getElementById("edusrc-opt-exclude-failed")?.checked,
      includePending: !!document.getElementById("edusrc-opt-include-pending")?.checked,
    };
  }

  function applyOptionsToUI(options) {
    const ex = document.getElementById("edusrc-opt-exclude-failed");
    const pe = document.getElementById("edusrc-opt-include-pending");
    if (ex) ex.checked = options.excludeFailed !== false;
    if (pe) pe.checked = !!options.includePending;
  }

  async function onOptionsChanged() {
    const opts = readMatchOptionsFromUI();
    await saveMatchOptions(opts);
    if (!lastScan?.vulns?.length) {
      await runScan();
      return;
    }
    const api = globalThis.EdusrcApi;
    if (api?.rematchScan) {
      const updated = api.rematchScan(lastScan, opts);
      lastScan = updated;
      await send({ type: "SAVE_SCAN", scan: updated });
      renderPanel(updated);
      if (isGiftPage) highlightGifts(updated.results);
    }
  }

  function send(msg) {
    return new Promise((resolve, reject) => {
      const timer = setTimeout(() => reject(new Error("扩展响应超时，请刷新页面重试")), 180000);
      try {
        chrome.runtime.sendMessage(msg, (res) => {
          clearTimeout(timer);
          if (chrome.runtime.lastError) {
            reject(new Error(chrome.runtime.lastError.message));
            return;
          }
          resolve(res);
        });
      } catch (err) {
        clearTimeout(timer);
        reject(err);
      }
    });
  }

  function setBody(html) {
    const body = document.getElementById("edusrc-panel-body");
    if (body) body.innerHTML = html;
  }

  function showProgressBar(show) {
    const bar = document.getElementById("edusrc-panel-progress");
    if (bar) bar.classList.toggle("hidden", !show);
  }

  function updateProgressBar(p) {
    if (!p) return;
    showProgressBar(true);
    const text = document.getElementById("edusrc-progress-text");
    const pct = document.getElementById("edusrc-progress-pct");
    const bar = document.getElementById("edusrc-progress-bar");
    const percent = p.percent ?? 0;
    if (text) text.textContent = p.text || "扫描中…";
    if (pct) pct.textContent = `${percent}%`;
    if (bar) bar.style.width = `${percent}%`;
    if (!p.running && percent >= 100) {
      setTimeout(() => showProgressBar(false), 600);
    }
  }

  function createFab() {
    if (document.getElementById("edusrc-cert-badge")) return;

    const wrap = document.createElement("div");
    wrap.id = "edusrc-cert-badge";
    wrap.innerHTML = `
      <div id="edusrc-cert-panel">
        <h3>可兑换证书</h3>
        <div id="edusrc-panel-body"><div class="empty">加载中…</div></div>
        <div id="edusrc-panel-progress" class="scan-progress hidden">
          <div class="scan-progress-row">
            <span id="edusrc-progress-text">扫描中…</span>
            <span id="edusrc-progress-pct">0%</span>
          </div>
          <div class="scan-progress-track">
            <div id="edusrc-progress-bar" class="scan-progress-bar"></div>
          </div>
        </div>
        <div class="filter-opts">
          <label><input type="checkbox" id="edusrc-opt-exclude-failed" checked /> 排除未通过</label>
          <label><input type="checkbox" id="edusrc-opt-include-pending" /> 计入待审核</label>
        </div>
        <button class="scan-btn" id="edusrc-panel-scan">重新扫描</button>
      </div>
      <button class="fab" title="EDUSRC 证书助手">🎓<span class="count hidden" id="edusrc-fab-count">0</span></button>
    `;
    document.body.appendChild(wrap);

    wrap.querySelector(".fab").addEventListener("click", () => {
      wrap.querySelector("#edusrc-cert-panel").classList.toggle("open");
    });

    wrap.querySelector("#edusrc-panel-scan").addEventListener("click", async (e) => {
      e.stopPropagation();
      await runScan();
    });

    wrap.querySelector("#edusrc-opt-exclude-failed").addEventListener("change", () => {
      onOptionsChanged().catch(() => {});
    });
    wrap.querySelector("#edusrc-opt-include-pending").addEventListener("change", () => {
      onOptionsChanged().catch(() => {});
    });

    document.addEventListener("click", (e) => {
      if (!wrap.contains(e.target)) {
        wrap.querySelector("#edusrc-cert-panel").classList.remove("open");
      }
    });
  }

  function escapeHtml(s) {
    const d = document.createElement("div");
    d.textContent = s || "";
    return d.innerHTML;
  }

  function renderCertItem(r, cssClass) {
    const label = r.name || r.source || "证书";
    const note = r.statusNote || r.reason || "";
    return `<div class="item ${cssClass || ""}"><a href="${escapeHtml(r.url)}" target="_blank">${escapeHtml(label)}</a><div class="meta">${escapeHtml(note)}</div></div>`;
  }

  function renderPanel(scan) {
    lastScan = scan;
    showProgressBar(false);
    const body = document.getElementById("edusrc-panel-body");
    const countEl = document.getElementById("edusrc-fab-count");
    if (!body) return;

    if (!scan?.results) {
      body.innerHTML = '<div class="empty">点击「重新扫描」开始匹配</div>';
      countEl?.classList.add("hidden");
      return;
    }

    const eligible = scan.results.filter((r) => r.eligible);
    const sameSchool = scan.results.filter(
      (r) => !r.eligible && r.relatedVulns?.length > 0
    );

    if (eligible.length || sameSchool.length) {
      if (countEl) {
        countEl.textContent = eligible.length || sameSchool.length;
        countEl.classList.remove("hidden");
        const hasPreview = eligible.some((r) => r.preview);
        if (!eligible.length || hasPreview) countEl.style.background = "#f59e0b";
        else countEl.style.background = "";
      }

      let html = "";
      if (eligible.length) {
        html += eligible.map((r) => renderCertItem(r, r.preview ? "preview" : "ok")).join("");
      }
      if (sameSchool.length) {
        if (eligible.length) {
          html += `<div class="section-label">同校证书（暂未满足）</div>`;
        }
        html += sameSchool.map((r) => renderCertItem(r, "pending")).join("");
      }
      body.innerHTML = html;
    } else {
      countEl?.classList.add("hidden");
      let hint = "暂无满足条件的证书";
      const countable = scan.countableCount ?? scan.approvedCount;
      const stats = scan.giftCount
        ? `<br><span style="color:#94a3b8;font-size:11px">已扫描 ${scan.giftCount} 个证书 · 计入 ${countable}/${scan.vulnCount} 条漏洞</span>`
        : "";
      if (scan.hints?.length) {
        hint += `<br><span style="color:#64748b;font-size:11px;margin-top:6px;display:inline-block">${scan.hints.map(escapeHtml).join("<br>")}</span>`;
      }
      body.innerHTML = `<div class="empty">${hint}${stats}</div>`;
    }

    if (isGiftPage) highlightGifts(scan.results);
  }

  function highlightGifts(results) {
    if (!results) return;
    document.querySelectorAll(".edusrc-gift-tag").forEach((el) => el.remove());
    document.querySelectorAll(".edusrc-gift-highlight").forEach((el) =>
      el.classList.remove("edusrc-gift-highlight")
    );

    const map = new Map(results.map((r) => [r.id, r]));

    document.querySelectorAll('a[href*="/gift/"]').forEach((a) => {
      const m = a.getAttribute("href").match(/\/gift\/(\d+)\//);
      if (!m) return;
      const item = map.get(m[1]);
      if (!item) return;

      const li = a.closest("li") || a.closest(".pic")?.parentElement;
      if (!li || li.querySelector(".edusrc-gift-tag")) return;

      if (item.eligible) li.classList.add("edusrc-gift-highlight");

      const tag = document.createElement("span");
      tag.className = "edusrc-gift-tag" + (item.eligible ? "" : " no");
      tag.textContent = item.preview ? "⏳ 待审核" : item.eligible ? "✓ 可兑换" : "未满足";
      const caption = li.querySelector(".pic-caption");
      if (caption) caption.appendChild(tag);
    });
  }

  async function runScan() {
    setBody('<div class="empty">正在扫描…</div>');
    updateProgressBar({ text: "开始扫描…", percent: 0, running: true });

    try {
      await send({ type: "ENSURE_ENGINE" });
    } catch {
      /* fallback */
    }

    const api = globalThis.EdusrcApi;
    const parser = globalThis.EdusrcParser;

    if (api && parser) {
      try {
        const matchOptions = readMatchOptionsFromUI();
        await saveMatchOptions(matchOptions);
        const scan = await api.runScan((p) => {
          updateProgressBar(p);
          send({ type: "SET_PROGRESS", progress: p }).catch(() => {});
        }, matchOptions);
        await send({ type: "SAVE_SCAN", scan });
        renderPanel(scan);
        return;
      } catch (err) {
        showProgressBar(false);
        const msg = err.message === "NOT_LOGGED_IN" ? "请先登录 EDUSRC" : err.message;
        setBody(`<div class="empty">${msg}</div>`);
        return;
      }
    }

    try {
      const res = await send({ type: "START_SCAN", matchOptions: readMatchOptionsFromUI() });
      if (!res?.ok) {
        showProgressBar(false);
        setBody(
          res?.error === "NOT_LOGGED_IN"
            ? '<div class="empty">请先登录 EDUSRC</div>'
            : `<div class="empty">扫描失败：${res?.error || "未知错误"}</div>`
        );
        return;
      }
      renderPanel(res.scan);
    } catch (err) {
      showProgressBar(false);
      setBody(`<div class="empty">${err.message}</div>`);
    }
  }

  async function loadSession() {
    const parser = globalThis.EdusrcParser;
    const api = globalThis.EdusrcApi;

    if (parser && api) {
      const session = await parser.detectSession(api.fetchPage);
      if (!session.loggedIn) return { ok: false, error: "NOT_LOGGED_IN" };
      const userId = session.userId || "self";
      const cached = await send({ type: "LOAD_CACHE", userId });
      return { ok: true, userId, scan: cached?.scan || null };
    }

    const res = await send({ type: "GET_CACHED" });
    if (!res?.ok) return { ok: false, error: res?.error || "加载失败" };
    return { ok: true, userId: res.userId, scan: res.scan || null };
  }

  chrome.runtime.onMessage.addListener((msg) => {
    if (msg.type === "SET_PROGRESS") updateProgressBar(msg.progress);
    if (msg.type === "SCAN_DONE" && msg.scan) renderPanel(msg.scan);
  });

  async function init() {
    if (isLoginPage) return;

    createFab();

    const savedOpts = await loadMatchOptions();
    applyOptionsToUI(savedOpts);

    try {
      await send({ type: "ENSURE_ENGINE" });
    } catch {
      /* ignore */
    }

    if (!globalThis.EdusrcApi || !globalThis.EdusrcParser) {
      setBody('<div class="empty">核心模块未加载，请刷新页面 (F5)</div>');
      return;
    }

    try {
      const session = await loadSession();

      if (!session.ok) {
        setBody(
          session.error === "NOT_LOGGED_IN"
            ? '<div class="empty">请先登录 EDUSRC</div>'
            : `<div class="empty">${session.error}</div>`
        );
        return;
      }

      if (session.scan) {
        if (session.scan.matchOptions) applyOptionsToUI(session.scan.matchOptions);
        renderPanel(session.scan);
        if (isGiftPage) highlightGifts(session.scan.results);
        return;
      }

      await runScan();
    } catch (err) {
      setBody(`<div class="empty">${err.message}</div>`);
    }
  }

  if (document.readyState === "loading") {
    document.addEventListener("DOMContentLoaded", init);
  } else {
    init();
  }
})();
