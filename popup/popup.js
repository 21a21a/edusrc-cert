const $ = (sel) => document.querySelector(sel);

let lastScan = null;

function send(msg) {
  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("扩展响应超时")), 120000);
    chrome.runtime.sendMessage(msg, (res) => {
      clearTimeout(timer);
      if (chrome.runtime.lastError) {
        reject(new Error(chrome.runtime.lastError.message));
        return;
      }
      resolve(res);
    });
  });
}

function formatTime(ts) {
  if (!ts) return "";
  const d = new Date(ts);
  return `更新于 ${d.getMonth() + 1}/${d.getDate()} ${String(d.getHours()).padStart(2, "0")}:${String(d.getMinutes()).padStart(2, "0")}`;
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
    excludeFailed: !!$("#opt-exclude-failed")?.checked,
    includePending: !!$("#opt-include-pending")?.checked,
  };
}

function applyOptionsToUI(options) {
  if ($("#opt-exclude-failed")) $("#opt-exclude-failed").checked = options.excludeFailed !== false;
  if ($("#opt-include-pending")) $("#opt-include-pending").checked = !!options.includePending;
}

async function rematchWithOptions() {
  const opts = readMatchOptionsFromUI();
  await saveMatchOptions(opts);
  if (!lastScan?.vulns?.length) {
    await startScan();
    return;
  }
  const res = await send({ type: "REMATCH_SCAN", scan: lastScan, matchOptions: opts });
  if (res?.ok && res.scan) {
    lastScan = res.scan;
    showStats(res.scan);
    renderResults(res.scan);
  }
}

function renderResults(scan) {
  lastScan = scan;
  const container = $("#results");
  if (!scan?.results?.length) {
    container.innerHTML = '<div class="empty">暂无证书数据</div>';
    return;
  }

  const eligible = scan.results.filter((r) => r.eligible);
  const sameSchool = scan.results.filter((r) => !r.eligible && r.relatedVulns?.length > 0);
  const ineligible = scan.results.filter((r) => !r.eligible && !r.relatedVulns?.length);

  let html = "";

  if (eligible.length) {
    html += `<div class="section-title">✅ 可兑换 (${eligible.length})</div>`;
    html += eligible.map((r) => renderCard({ ...r, _note: r.statusNote || r.reason })).join("");
  }

  if (sameSchool.length) {
    html += `<div class="section-title">🏫 同校证书·暂未满足 (${sameSchool.length})</div>`;
    html += sameSchool.map((r) => renderCard({ ...r, _note: r.statusNote || r.reason })).join("");
  }

  if (!eligible.length && !sameSchool.length) {
    html += '<div class="empty">暂无满足条件的证书</div>';
    if (scan.hints?.length) {
      html += `<div class="empty" style="text-align:left;font-size:12px;color:#64748b">${scan.hints.map(escapeHtml).join("<br>")}</div>`;
    }
  }

  if (ineligible.length) {
    html += `<div class="section-title">其他未满足 (${ineligible.length})</div>`;
    html += ineligible.slice(0, 8).map(renderCard).join("");
    if (ineligible.length > 8) {
      html += `<div class="empty">还有 ${ineligible.length - 8} 个未显示…</div>`;
    }
  }

  container.innerHTML = html;
}

function renderCard(item) {
  const vulnsHtml =
    item.matchedVulns?.length && item.eligible
      ? `<details class="card-vulns"><summary>匹配漏洞 (${item.matchedVulns.length})</summary>${item.matchedVulns
          .map(
            (v) =>
              `<div class="vuln-item"><a href="${escapeHtml(v.url)}" target="_blank">${escapeHtml(v.date)} ${escapeHtml(v.title)}</a> · ${escapeHtml(v.severity)}</div>`
          )
          .join("")}</details>`
      : "";

  const issues = item._note || item.issues?.length ? item.issues.join("；") : item.statusNote || item.reason;

  return `
    <div class="card ${item.eligible ? "eligible" : ""}">
      <div class="card-head">
        <div class="card-title">${escapeHtml(item.name || item.source)}</div>
        <span class="badge ${item.eligible ? (item.preview ? "pending" : "ok") : "no"}">${item.eligible ? (item.preview ? "待审核" : "可兑换") : "不可"}</span>
      </div>
      <div class="card-meta">库存 ${item.stock} · ${escapeHtml(item.source || "")}</div>
      <div class="card-reason">${escapeHtml(issues || "")}</div>
      ${vulnsHtml}
      <a class="card-link" href="${escapeHtml(item.url)}" target="_blank">查看证书详情 →</a>
    </div>`;
}

function escapeHtml(s) {
  const d = document.createElement("div");
  d.textContent = s || "";
  return d.innerHTML;
}

function showStats(scan) {
  const stats = $("#stats");
  stats.classList.remove("hidden");
  const countable = scan.countableCount ?? scan.approvedCount;
  $("#stat-vulns").textContent = `计入 ${countable}/${scan.vulnCount} 漏洞 · ${scan.giftCount || "?"} 个证书`;
  $("#stat-time").textContent = formatTime(scan.scannedAt);
}

async function checkLogin() {
  const res = await send({ type: "CHECK_LOGIN" });
  const hint = $("#login-hint");
  const btn = $("#btn-scan");

  if (res.loggedIn) {
    hint.classList.add("hidden");
    btn.disabled = false;
    return true;
  }

  hint.classList.remove("hidden");
  hint.innerHTML =
    '请先在浏览器中登录 <a href="https://src.sjtu.edu.cn/login/" target="_blank">EDUSRC</a> 后再使用本插件。';
  btn.disabled = true;
  return false;
}

async function loadCached() {
  const res = await send({ type: "GET_CACHED" });
  if (res.ok && res.scan) {
    if (res.scan.matchOptions) applyOptionsToUI(res.scan.matchOptions);
    showStats(res.scan);
    renderResults(res.scan);
  }
}

let progressTimer = null;

function updateProgressBar(p) {
  const el = $("#progress");
  el.classList.remove("hidden");
  $("#progress-text").textContent = p?.text || "扫描中…";
  const pct = p?.percent ?? 0;
  $("#progress-pct").textContent = `${pct}%`;
  $("#progress-bar").style.width = `${pct}%`;
}

function startProgressPoll() {
  const el = $("#progress");
  el.classList.remove("hidden");
  updateProgressBar({ text: "扫描中…", percent: 0 });
  progressTimer = setInterval(async () => {
    try {
      const p = await send({ type: "GET_PROGRESS" });
      if (p) updateProgressBar(p);
      if (!p?.running) clearInterval(progressTimer);
    } catch {
      clearInterval(progressTimer);
    }
  }, 300);
}

async function startScan() {
  const btn = $("#btn-scan");
  btn.disabled = true;
  btn.textContent = "扫描中…";
  startProgressPoll();

  try {
    const matchOptions = readMatchOptionsFromUI();
    await saveMatchOptions(matchOptions);
    const res = await send({ type: "START_SCAN", matchOptions });
    if (!res?.ok) {
      if (res?.error === "NOT_LOGGED_IN") {
        $("#login-hint").classList.remove("hidden");
      } else {
        alert("扫描失败：" + (res?.error || "未知错误"));
      }
      return;
    }
    showStats(res.scan);
    renderResults(res.scan);
  } catch (err) {
    alert("扫描失败：" + err.message);
  } finally {
    clearInterval(progressTimer);
    $("#progress").classList.add("hidden");
    btn.disabled = false;
    btn.textContent = "重新扫描";
    await checkLogin();
  }
}

document.addEventListener("DOMContentLoaded", async () => {
  const savedOpts = await loadMatchOptions();
  applyOptionsToUI(savedOpts);

  const loggedIn = await checkLogin();
  if (loggedIn) await loadCached();
  $("#btn-scan").addEventListener("click", startScan);
  $("#opt-exclude-failed").addEventListener("change", () => rematchWithOptions().catch(() => {}));
  $("#opt-include-pending").addEventListener("change", () => rematchWithOptions().catch(() => {}));
});
