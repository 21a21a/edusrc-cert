(function () {
  if (window.__edusrcCertBadge) return;
  window.__edusrcCertBadge = true;

  const isGiftPage = location.pathname.startsWith("/gift");
  const giftTypeParam = new URLSearchParams(location.search).get("gift_type");
  const isTangiblePage = giftTypeParam === "tangible_gift";
  const isCertPage = !giftTypeParam || giftTypeParam === "certificate";
  let lastSelfScan = null;
  let lastUserScan = null;
  let panelMode = "self";

  function scanModeOf(scan) {
    return scan?.scanMode === "user" ? "user" : "self";
  }

  function storeScan(scan) {
    if (!scan) return;
    if (scanModeOf(scan) === "user") lastUserScan = scan;
    else lastSelfScan = scan;
  }

  function setEmptyPanel(mode) {
    document.getElementById("edusrc-fab-count")?.classList.add("hidden");
    setBody(
      mode === "user"
        ? '<div class="empty">输入用户 ID 后点击「分析」</div>'
        : '<div class="empty">点击「重新扫描」开始匹配</div>'
    );
  }

  async function switchPanelMode(mode) {
    setPanelMode(mode);
    showProgressBar(false);

    let scan = null;
    if (mode === "self") {
      scan = lastSelfScan;
      if (!scan) {
        const session = await loadSession();
        if (session.ok && session.scan) {
          lastSelfScan = session.scan;
          scan = session.scan;
        }
      }
    } else {
      const id =
        parseUserIdInput(document.getElementById("edusrc-user-id")?.value) ||
        getOtherProfileUserId();
      if (id && lastUserScan?.targetUser?.userId === id) {
        scan = lastUserScan;
      } else if (id) {
        const cached = await send({ type: "LOAD_USER_CACHE", targetUserId: id });
        if (cached?.scan) {
          lastUserScan = cached.scan;
          scan = cached.scan;
        } else {
          lastUserScan = null;
        }
      } else {
        lastUserScan = null;
      }
    }

    if (scan) {
      if (scan.matchOptions) applyOptionsToUI(scan.matchOptions);
      renderPanelBody(scan);
      if (isGiftPage && mode === "self") highlightGifts(scan.results, scan.tangibleResults);
    } else {
      setEmptyPanel(mode);
    }
  }

  function getOtherProfileUserId() {
    const m = location.pathname.match(/^\/profile\/(\d+)\/?$/);
    return m ? m[1] : null;
  }

  function parseUserIdInput(raw) {
    const s = (raw || "").trim();
    const m = s.match(/\/profile\/(\d+)\/?/);
    if (m) return m[1];
    if (/^\d+$/.test(s)) return s;
    return null;
  }

  function setPanelMode(mode) {
    panelMode = mode;
    document.querySelectorAll(".mode-tab").forEach((btn) => {
      btn.classList.toggle("active", btn.dataset.mode === mode);
    });
    const lookup = document.getElementById("edusrc-user-lookup");
    if (lookup) lookup.classList.toggle("hidden", mode !== "user");
    const scanBtn = document.getElementById("edusrc-panel-scan");
    if (scanBtn) {
      scanBtn.textContent = mode === "user" ? "重新分析" : "重新扫描";
    }
  }

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
    if (panelMode === "user") {
      const active = lastUserScan;
      if (active?.vulns?.length) {
        const api = globalThis.EdusrcApi;
        if (api?.rematchUserScan) {
          const updated = api.rematchUserScan(active, opts);
          lastUserScan = updated;
          await send({
            type: "SAVE_USER_SCAN",
            targetUserId: updated.targetUser?.userId,
            scan: updated,
          });
          renderPanelBody(updated);
          return;
        }
      }
      const id = parseUserIdInput(document.getElementById("edusrc-user-id")?.value);
      if (id) await runUserScan(id);
      return;
    }

    const active = lastSelfScan;
    if (!active?.vulns?.length) {
      await runScan();
      return;
    }
    const api = globalThis.EdusrcApi;
    if (api?.rematchScan) {
      const updated = api.rematchScan(active, opts);
      lastSelfScan = updated;
      await send({ type: "SAVE_SCAN", scan: updated });
      renderPanelBody(updated);
      if (isGiftPage) highlightGifts(updated.results, updated.tangibleResults);
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
        <h3>礼品助手</h3>
        <div class="mode-tabs">
          <button type="button" class="mode-tab active" data-mode="self">我的</button>
          <button type="button" class="mode-tab" data-mode="user">他人</button>
        </div>
        <div id="edusrc-user-lookup" class="user-lookup hidden">
          <input id="edusrc-user-id" type="text" placeholder="用户 ID 或 profile 链接" />
          <button type="button" id="edusrc-user-scan-btn">分析</button>
        </div>
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
      <button class="fab" title="EDUSRC 礼品助手">🎓<span class="count hidden" id="edusrc-fab-count">0</span></button>
    `;
    document.body.appendChild(wrap);

    wrap.querySelector(".fab").addEventListener("click", () => {
      wrap.querySelector("#edusrc-cert-panel").classList.toggle("open");
    });

    wrap.querySelector("#edusrc-panel-scan").addEventListener("click", async (e) => {
      e.stopPropagation();
      if (panelMode === "user") {
        const id = parseUserIdInput(document.getElementById("edusrc-user-id")?.value);
        if (!id) {
          setBody('<div class="empty">请输入用户 ID 或 profile 链接</div>');
          return;
        }
        await runUserScan(id);
      } else {
        await runScan();
      }
    });

    wrap.querySelectorAll(".mode-tab").forEach((btn) => {
      btn.addEventListener("click", (e) => {
        e.stopPropagation();
        if (btn.dataset.mode === panelMode) return;
        if (btn.dataset.mode === "user") {
          const otherId = getOtherProfileUserId();
          if (otherId) document.getElementById("edusrc-user-id").value = otherId;
        }
        switchPanelMode(btn.dataset.mode).catch(() => {});
      });
    });

    wrap.querySelector("#edusrc-user-scan-btn").addEventListener("click", async (e) => {
      e.stopPropagation();
      const id = parseUserIdInput(document.getElementById("edusrc-user-id")?.value);
      if (!id) {
        setBody('<div class="empty">请输入用户 ID 或 profile 链接</div>');
        return;
      }
      setPanelMode("user");
      await runUserScan(id);
    });

    wrap.querySelector("#edusrc-user-id").addEventListener("keydown", (e) => {
      if (e.key === "Enter") {
        e.preventDefault();
        wrap.querySelector("#edusrc-user-scan-btn").click();
      }
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

  function renderTangibleItem(r, cssClass) {
    const label = r.name || "实物礼物";
    const note = r.statusNote || r.issues?.join("；") || "";
    const previewCls = r.preview ? " preview" : "";
    return `<div class="item ${cssClass || ""}${previewCls}"><a href="${escapeHtml(r.url)}" target="_blank">${escapeHtml(label)}</a><div class="meta">${escapeHtml(note)} · 库存 ${r.stock}</div></div>`;
  }

  function renderScanHeader(scan) {
    if (scan.scanMode !== "user" || !scan.targetUser) return "";
    const u = scan.targetUser;
    const coinPart = scan.coinsEstimated
      ? ` · 金币约 ${scan.coins ?? "?"}（Rank 估算）`
      : scan.coins !== null && scan.coins !== undefined
        ? ` · 金币 ${scan.coins}`
        : "";
    return `<div class="user-header"><a href="${escapeHtml(u.profileUrl)}" target="_blank">${escapeHtml(u.nickname)}</a> · Rank ${u.rank ?? "?"}${coinPart}</div>`;
  }

  function renderPanel(scan) {
    storeScan(scan);
    if (scanModeOf(scan) !== panelMode) return;
    renderPanelBody(scan);
  }

  function renderPanelBody(scan) {
    if (scan.scanMode === "user") renderPanelBodyUser(scan);
    else renderPanelBodySelf(scan);
  }

  function renderPanelBodyUser(scan) {
    showProgressBar(false);
    const body = document.getElementById("edusrc-panel-body");
    const countEl = document.getElementById("edusrc-fab-count");
    if (!body) return;

    if (!scan?.results) {
      body.innerHTML = '<div class="empty">输入用户 ID 后点击「分析」</div>';
      countEl?.classList.add("hidden");
      return;
    }

    const eligible = scan.results.filter((r) => r.eligible);
    const tangibleEligible = (scan.tangibleResults || []).filter((r) => r.eligible);

    let html = renderScanHeader(scan);

    if (eligible.length) {
      html += `<div class="section-label">漏洞证书 · 可兑换 (${eligible.length})</div>`;
      html += eligible.map((r) => renderCertItem(r, r.preview ? "preview" : "ok")).join("");
    }
    if (tangibleEligible.length) {
      html += `<div class="section-label">实物礼物 · 可兑换 (${tangibleEligible.length})</div>`;
      html += tangibleEligible.slice(0, 8).map((r) => renderTangibleItem(r, "ok")).join("");
      if (tangibleEligible.length > 8) {
        html += `<div class="empty" style="padding:8px 0">还有 ${tangibleEligible.length - 8} 个可兑换…</div>`;
      }
    }

    if (!eligible.length && !tangibleEligible.length) {
      countEl?.classList.add("hidden");
      html += '<div class="empty">暂无可兑换礼品</div>';
    } else if (countEl) {
      countEl.textContent = eligible.length + tangibleEligible.length;
      countEl.classList.remove("hidden");
      const hasPreview =
        eligible.some((r) => r.preview) || tangibleEligible.some((r) => r.preview);
      countEl.style.background = hasPreview ? "#f59e0b" : "";
    }

    body.innerHTML = html;
  }

  function renderPanelBodySelf(scan) {
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
    const tangibleEligible = (scan.tangibleResults || []).filter((r) => r.eligible);
    const tangibleNear = (scan.tangibleResults || []).filter(
      (r) =>
        !r.eligible &&
        r.stock > 0 &&
        r.relatedVulns?.length > 0 &&
        (scan.coins === null || r.price <= scan.coins + 5)
    ).slice(0, 3);

    const totalHighlight = eligible.length + tangibleEligible.length || sameSchool.length;

    if (eligible.length || sameSchool.length || tangibleEligible.length) {
      if (countEl) {
        countEl.textContent = totalHighlight || sameSchool.length;
        countEl.classList.remove("hidden");
        const hasPreview =
          eligible.some((r) => r.preview) || tangibleEligible.some((r) => r.preview);
        if ((!eligible.length && !tangibleEligible.length) || hasPreview) countEl.style.background = "#f59e0b";
        else countEl.style.background = "";
      }

      let html = "";
      if (scan.coins !== null && scan.coins !== undefined) {
        html += `<div class="coins-bar">金币 ${scan.coins}</div>`;
      }
      if (eligible.length) {
        html += `<div class="section-label">漏洞证书</div>`;
        html += eligible.map((r) => renderCertItem(r, r.preview ? "preview" : "ok")).join("");
      }
      if (sameSchool.length) {
        html += `<div class="section-label">同校证书（暂未满足）</div>`;
        html += sameSchool.map((r) => renderCertItem(r, "pending")).join("");
      }
      if (tangibleEligible.length) {
        html += `<div class="section-label">实物礼物 · 可兑换 (${tangibleEligible.length})</div>`;
        html += tangibleEligible.slice(0, 8).map((r) => renderTangibleItem(r, "ok")).join("");
        if (tangibleEligible.length > 8) {
          html += `<div class="empty" style="padding:8px 0">还有 ${tangibleEligible.length - 8} 个可兑换…</div>`;
        }
      } else if (scan.tangibleResults?.length) {
        html += `<div class="section-label">实物礼物</div>`;
        html += `<div class="empty" style="padding:8px 0">暂无买得起的实物</div>`;
        if (tangibleNear.length) {
          html += tangibleNear.map((r) => renderTangibleItem(r, "pending")).join("");
        }
      }
      body.innerHTML = html;
    } else {
      const hasTangible = scan.tangibleResults?.length > 0;
      if (hasTangible) {
        if (countEl) countEl.classList.add("hidden");
        let html = "";
        if (scan.coins !== null && scan.coins !== undefined) {
          html += `<div class="coins-bar">金币 ${scan.coins}</div>`;
        }
        html += `<div class="section-label">实物礼物</div>`;
        html += `<div class="empty" style="padding:8px 0">暂无买得起的实物</div>`;
        if (tangibleNear.length) {
          html += tangibleNear.map((r) => renderTangibleItem(r, "pending")).join("");
        }
        body.innerHTML = html;
      } else {
        countEl?.classList.add("hidden");
        let hint = "暂无满足条件的礼品";
        const countable = scan.countableCount ?? scan.approvedCount;
        const coinText = scan.coins !== null && scan.coins !== undefined ? ` · 金币 ${scan.coins}` : "";
        const stats = scan.giftCount
          ? `<br><span style="color:#94a3b8;font-size:11px">已扫描 ${scan.giftCount} 个证书 · ${scan.tangibleCount || 0} 个实物${coinText} · 计入 ${countable}/${scan.vulnCount} 条漏洞</span>`
          : "";
        if (scan.hints?.length) {
          hint += `<br><span style="color:#64748b;font-size:11px;margin-top:6px;display:inline-block">${scan.hints.map(escapeHtml).join("<br>")}</span>`;
        }
        body.innerHTML = `<div class="empty">${hint}${stats}</div>`;
      }
    }

    if (isGiftPage) highlightGifts(scan.results, scan.tangibleResults);
  }

  function highlightGifts(certResults, tangibleResults) {
    if (isCertPage && certResults) highlightGiftResults(certResults);
    if (isTangiblePage && tangibleResults) highlightGiftResults(tangibleResults);
  }

  function highlightGiftResults(results) {
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

  async function runUserScan(targetUserId) {
    setBody('<div class="empty">正在分析他人…</div>');
    updateProgressBar({ text: "开始分析…", percent: 0, running: true });

    try {
      await send({ type: "ENSURE_ENGINE" });
    } catch {
      /* fallback */
    }

    const api = globalThis.EdusrcApi;
    if (api?.runUserScan) {
      try {
        const matchOptions = readMatchOptionsFromUI();
        await saveMatchOptions(matchOptions);
        const scan = await api.runUserScan(
          targetUserId,
          (p) => {
            updateProgressBar(p);
            send({ type: "SET_PROGRESS", progress: p }).catch(() => {});
          },
          matchOptions
        );
        await send({
          type: "SAVE_USER_SCAN",
          targetUserId: String(targetUserId),
          scan,
        });
        setPanelMode("user");
        renderPanel(scan);
        return;
      } catch (err) {
        showProgressBar(false);
        const msg =
          err.message === "NOT_LOGGED_IN"
            ? "请先登录 EDUSRC"
            : err.message === "USER_NOT_FOUND"
              ? "用户不存在或主页未公开"
              : err.message;
        setBody(`<div class="empty">${msg}</div>`);
        return;
      }
    }

    try {
      const res = await send({
        type: "START_USER_SCAN",
        targetUserId,
        matchOptions: readMatchOptionsFromUI(),
      });
      if (!res?.ok) {
        showProgressBar(false);
        const errMsg =
          res?.error === "NOT_LOGGED_IN"
            ? "请先登录 EDUSRC"
            : res?.error === "USER_NOT_FOUND"
              ? "用户不存在或主页未公开"
              : res?.error || "分析失败";
        setBody(`<div class="empty">${errMsg}</div>`);
        return;
      }
      setPanelMode("user");
      renderPanel(res.scan);
    } catch (err) {
      showProgressBar(false);
      setBody(`<div class="empty">${err.message}</div>`);
    }
  }

  async function loadOrScanUser(targetUserId) {
    const cached = await send({ type: "LOAD_USER_CACHE", targetUserId: String(targetUserId) });
    if (cached?.scan) {
      lastUserScan = cached.scan;
      if (cached.scan.matchOptions) applyOptionsToUI(cached.scan.matchOptions);
      setPanelMode("user");
      renderPanelBody(cached.scan);
      return;
    }
    await runUserScan(targetUserId);
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
    if (msg.type === "SCAN_DONE" && msg.scan) {
      storeScan(msg.scan);
      if (scanModeOf(msg.scan) === panelMode) renderPanelBody(msg.scan);
    }
  });

  async function init() {
    if (location.pathname.startsWith("/login")) return;

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
      const otherId = getOtherProfileUserId();
      if (otherId) {
        setPanelMode("user");
        document.getElementById("edusrc-user-id").value = otherId;
        await loadOrScanUser(otherId);
        return;
      }

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
        lastSelfScan = session.scan;
        if (session.scan.matchOptions) applyOptionsToUI(session.scan.matchOptions);
        renderPanelBody(session.scan);
        if (isGiftPage) highlightGifts(session.scan.results, session.scan.tangibleResults);
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
