(function (g) {
  const ENGINE_VERSION = 7;
  if (g.__EDUSRC_ENGINE_V__ === ENGINE_VERSION && g.EdusrcParser) return;
  delete g.EdusrcParser;
  delete g.EdusrcMatcher;
  delete g.EdusrcApi;
  g.__EDUSRC_ENGINE_V__ = ENGINE_VERSION;

  const SEVERITY_MAP = { 低危: 1, 中危: 2, 高危: 3, 严重: 4 };

  function parseHtml(html) {
    return new DOMParser().parseFromString(html, "text/html");
  }

  function isLoginPage(html) {
    if (/href="\/logout\/"|>退出</.test(html)) return false;
    if (/href="\/add\/"|用户中心|我提交的漏洞|我的漏洞/.test(html)) return false;
    if (/href="\/post\/\d+\/"/.test(html)) return false;
    if (/我的漏洞|提交的漏洞|漏洞管理|礼品兑换|个人中心/.test(html)) return false;
    if (/\/media\/mugshot\/\d+\//.test(html)) return false;

    const hasTopbarLogin = /<a[^>]+href="\/login\/"[^>]*>\s*登录\s*<\/a>/.test(html);
    if (hasTopbarLogin) return true;

    return (
      /<title>\s*登录\s*\|/i.test(html) ||
      html.includes('<h1 style="text-align: center;">登录</h1>')
    );
  }

  function extractUserId(html) {
    const mugshot = html.match(/\/media\/mugshot\/(\d+)\//);
    if (mugshot) return mugshot[1];

    const all = [...html.matchAll(/href="\/profile\/(\d+)\/"/g)];
    for (const m of all) {
      if (m[1]) return m[1];
    }

    if (/href="\/logout\/"/.test(html) && !isLoginPage(html)) return "self";

    const doc = parseHtml(html);
    const profileLink = doc.querySelector('a[href^="/profile/"]');
    if (profileLink) {
      const match = profileLink.getAttribute("href").match(/\/profile\/(\d+)\//);
      if (match) return match[1];
    }
    return null;
  }

  async function detectSession(fetchPage) {
    const paths = [
      "/profile/post/",
      "/profile/",
      "/gift/?gift_type=certificate",
    ];
    let lastHtml = null;

    for (const path of paths) {
      try {
        const html = await fetchPage(path);
        if (isLoginPage(html)) continue;
        lastHtml = html;
        const userId = extractUserId(html);
        if (userId) return { loggedIn: true, userId, html };
      } catch {
        /* try next */
      }
    }

    if (lastHtml) return { loggedIn: true, userId: "self", html: lastHtml };
    return { loggedIn: false, userId: null, html: null };
  }

  function parseSeverityFromBadge(td) {
    if (!td) return null;
    const text = td.textContent.trim();
    for (const level of Object.keys(SEVERITY_MAP)) {
      if (text.includes(level)) return level;
    }
    return null;
  }

  function isApprovedStatus(status) {
    if (!status) return false;
    if (/待审核|审核中|未通过|拒绝/.test(status)) return false;
    if (/等待修复|已修复|已确认|已通过|已审核|修复中|已完成|确认/.test(status)) return true;
    return false;
  }

  function parseVulnTable(html) {
    const doc = parseHtml(html);
    const rows = doc.querySelectorAll("table.am-table tr, table.minos-list tr");
    const vulns = [];

    rows.forEach((row) => {
      if (row.classList.contains("am-primary") || row.classList.contains("null")) return;
      const cells = row.querySelectorAll("td");
      if (cells.length < 3) return;

      const link = row.querySelector('a[href*="/post/"]');
      if (!link) return;

      const href = link.getAttribute("href");
      const idMatch = href.match(/\/post\/(\d+)\//);
      if (!idMatch) return;

      const title = link.textContent.trim();
      const date = cells[0]?.textContent.trim() || "";

      let severity = null;
      let status = "";
      let rank = 0;

      if (cells.length >= 5) {
        severity = parseSeverityFromBadge(cells[2]);
        status = cells[3]?.textContent.trim() || "";
        const lastCell = cells[4]?.textContent.trim() || "";
        if (/^\d+$/.test(lastCell)) rank = parseInt(lastCell, 10);
      } else if (cells.length === 4) {
        severity = parseSeverityFromBadge(cells[2]);
        const c3 = cells[3]?.textContent.trim() || "";
        if (/待审核|等待修复|未通过|已确认/.test(c3)) {
          status = c3;
        } else if (/^\d+$/.test(c3)) {
          rank = parseInt(c3, 10);
        } else {
          severity = parseSeverityFromBadge(cells[2]) || parseSeverityFromBadge(cells[3]);
          status = c3;
        }
      } else {
        severity = parseSeverityFromBadge(cells[2]);
        rank = parseInt(cells[3]?.textContent.trim(), 10) || 0;
      }

      if (!severity) return;

      const approved = isApprovedStatus(status) || (!status && rank > 0);

      vulns.push({
        id: idMatch[1],
        url: `https://src.sjtu.edu.cn/post/${idMatch[1]}/`,
        title,
        date,
        severity,
        severityLevel: SEVERITY_MAP[severity],
        status: status || (rank > 0 ? "已确认" : "待审核"),
        rank,
        approved,
      });
    });

    return vulns;
  }

  function getMaxPage(html) {
    const doc = parseHtml(html);
    let max = 1;
    doc.querySelectorAll(".am-pagination a").forEach((a) => {
      const href = a.getAttribute("href") || "";
      const hm = href.match(/[?&]page=(\d+)/);
      if (hm) max = Math.max(max, parseInt(hm[1], 10));
      const text = a.textContent.trim();
      if (/^\d+$/.test(text)) max = Math.max(max, parseInt(text, 10));
    });
    const re = /[?&]page=(\d+)/g;
    let m;
    while ((m = re.exec(html))) max = Math.max(max, parseInt(m[1], 10));
    return max;
  }

  function parseGiftList(html) {
    const doc = parseHtml(html);
    const gifts = [];
    doc.querySelectorAll("ul.am-avg-sm-4 li, ul.am-thumbnails li").forEach((li) => {
      const link = li.querySelector('a[href*="/gift/"]');
      if (!link) return;
      const m = link.getAttribute("href").match(/\/gift\/(\d+)\//);
      if (!m) return;

      const ps = li.querySelectorAll("p");
      let stock = 0;
      let price = 0;
      ps.forEach((p) => {
        const t = p.textContent;
        const sm = t.match(/剩余数量[：:]\s*(\d+)/);
        const pm = t.match(/价格[：:]\s*(\d+)/);
        if (sm) stock = parseInt(sm[1], 10);
        if (pm) price = parseInt(pm[1], 10);
      });

      gifts.push({
        id: m[1],
        name: link.textContent.trim(),
        url: `https://src.sjtu.edu.cn/gift/${m[1]}/`,
        stock,
        price,
      });
    });
    return gifts;
  }

  function parseGiftDetail(html) {
    const doc = parseHtml(html);
    const result = { name: "", price: 0, stock: 0, source: "", description: "", limit: "" };

    doc.querySelectorAll(".am-g").forEach((row) => {
      const label = row.querySelector(".am-u-sm-2");
      const value = row.querySelector(".am-u-sm-10");
      if (!label || !value) return;
      const key = label.textContent.trim();
      const val = value.textContent.trim();

      switch (key) {
        case "名称":
          result.name = val;
          break;
        case "价格":
          result.price = parseInt(val.match(/(\d+)/)?.[1] || "0", 10);
          break;
        case "剩余数量":
          result.stock = parseInt(val.match(/(\d+)/)?.[1] || "0", 10);
          break;
        case "来源":
          result.source = val;
          break;
        case "描述":
          result.description = value.innerHTML
            .replace(/<br\s*\/?>/gi, "\n")
            .replace(/<[^>]+>/g, "")
            .trim();
          break;
        case "兑换限制":
          result.limit = val;
          break;
      }
    });

    return result;
  }

  g.EdusrcParser = {
    SEVERITY_MAP,
    isLoginPage,
    detectSession,
    extractUserId,
    parseVulnTable,
    getMaxPage,
    parseGiftList,
    parseGiftDetail,
  };
})(globalThis);

(function (g) {
  if (g.__EDUSRC_ENGINE_V__ !== 7 || !g.EdusrcParser) return;

  const { SEVERITY_MAP } = g.EdusrcParser;

  function normalizeSchool(name) {
    return name
      .replace(/[（(].*?[）)]/g, "")
      .replace(/版漏洞报送证书.*$/g, "")
      .replace(/漏洞报送证书.*$/g, "")
      .replace(/原创漏洞证书[-\s]*/g, "")
      .replace(/礼品[-\s]*/g, "")
      .replace(/\d{4}/g, "")
      .trim();
  }

  function resolveGiftSchool(gift) {
    if (gift.source) return gift.source;
    const desc = gift.description || "";
    const fromDesc = desc.match(/(?:至少)?提交过\s*\d+\s*个(.+?)的(?:中|高|低|严重)/);
    if (fromDesc) return fromDesc[1].trim();
    const fromName = (gift.name || "").match(
      /(?:原创漏洞证书[\s-]*)?(.+?)(?:版漏洞|漏洞报送|漏洞赏报送)/
    );
    if (fromName) return fromName[1].trim();
    return "";
  }

  const DEFAULT_MATCH_OPTIONS = { excludeFailed: true, includePending: false };

  function normalizeMatchOptions(opts) {
    return {
      excludeFailed: opts?.excludeFailed !== false,
      includePending: !!opts?.includePending,
    };
  }

  function isFailedVuln(v) {
    return /未通过|拒绝/.test(v.status || "");
  }

  function isPendingVuln(v) {
    if (v.approved || isFailedVuln(v)) return false;
    return /待审核|审核中/.test(v.status || "") || true;
  }

  function isCountableVuln(v, opts) {
    const o = normalizeMatchOptions(opts);
    if (o.excludeFailed && isFailedVuln(v)) return false;
    if (v.approved) return true;
    if (o.includePending && isPendingVuln(v)) return true;
    return false;
  }

  function describeCertStatus(school, evalResult, relatedVulns, eligible, issues, opts) {
    if (eligible) {
      const matched = evalResult.matchedVulns || [];
      const pendingOnly = matched.length > 0 && matched.every((v) => !v.approved);
      if (pendingOnly && normalizeMatchOptions(opts).includePending) {
        return `${evalResult.reason}（待审核，通过后正式可兑换）`;
      }
      return evalResult.reason;
    }
    if (!relatedVulns.length) return issues.join("；") || evalResult.reason;

    const approved = relatedVulns.filter((v) => v.approved);
    const pending = relatedVulns.filter((v) => !v.approved);

    if (pending.length && !approved.length) {
      const detail = pending
        .map((v) => `${v.severity}·${v.status || "待审核"}`)
        .join("、");
      return `你有该校漏洞（${detail}），审核通过后才可兑换`;
    }

    return issues.join("；") || evalResult.reason;
  }

  function buildScanHints(vulns, gifts, opts) {
    const hints = [];
    const o = normalizeMatchOptions(opts);
    const approved = vulns.filter((v) => v.approved);
    const pending = vulns.filter((v) => isPendingVuln(v));
    const failed = vulns.filter((v) => isFailedVuln(v));
    const year = new Date().getFullYear();

    if (!vulns.length) {
      return ["未读取到漏洞，请打开「我的漏洞」页后重新扫描"];
    }

    if (!o.includePending) {
      for (const v of pending) {
        const related = gifts.filter((g) => schoolMatches(v.title, resolveGiftSchool(g)));
        if (related.length) {
          const names = related
            .map((g) => normalizeSchool(resolveGiftSchool(g)))
            .slice(0, 2)
            .join("、");
          hints.push(
            `「${v.title}」${v.status || "待审核"}，勾选「计入待审核」可预览（${names}）`
          );
        }
      }
    }

    for (const v of approved) {
      const related = gifts.filter((g) => schoolMatches(v.title, resolveGiftSchool(g)));
      if (!related.length) {
        hints.push(`「${v.title}」礼品中心暂无对应证书`);
        continue;
      }
      const needsYear = related.some((g) => /兑换年度内|本年度|当年/.test(g.description || ""));
      const vulnYear = parseInt(v.date.slice(0, 4), 10);
      if (needsYear && vulnYear && vulnYear < year) {
        hints.push(`「${v.title}」为 ${vulnYear} 年漏洞，证书要求 ${year} 年度内`);
      }
    }

    const pendingNoCert = pending.filter(
      (v) => !gifts.some((g) => schoolMatches(v.title, resolveGiftSchool(g)))
    );
    if (o.excludeFailed && failed.length) {
      hints.push(`已排除 ${failed.length} 条未通过漏洞`);
    }
    if (!o.includePending && pendingNoCert.length) {
      hints.push(`${pendingNoCert.length} 条待审核漏洞暂无同校证书`);
    } else if (!o.includePending && pending.length) {
      hints.push(`${pending.length} 条待审核未计入（可勾选「计入待审核」）`);
    }

    return [...new Set(hints)].slice(0, 6);
  }

  function schoolMatches(vulnTitle, source) {
    if (!source) return false;
    const src = normalizeSchool(source);
    const title = vulnTitle.trim();
    if (!src || !title) return false;
    if (title.includes(src)) return true;
    if (title.length >= 4 && src.includes(title)) return true;
    return false;
  }

  function parseDate(s) {
    const [y, m, d] = s.split("-").map(Number);
    return new Date(y, m - 1, d || 1);
  }

  function extractDateRange(text) {
    if (/兑换年度内|本年度|当年/.test(text)) {
      const y = new Date().getFullYear();
      return { after: parseDate(`${y}-01-01`), before: parseDate(`${y}-12-31`) };
    }
    const range = text.match(/(\d{4})年\s*[-~至到]\s*(\d{4})年/);
    if (range) {
      return {
        after: parseDate(`${range[1]}-01-01`),
        before: parseDate(`${range[2]}-12-31`),
      };
    }
    const afterFull = text.match(/(\d{4})年(\d{1,2})月(\d{1,2})日?以后/);
    if (afterFull) {
      return { after: parseDate(`${afterFull[1]}-${afterFull[2]}-${afterFull[3]}`) };
    }
    const afterMonth = text.match(/(\d{4})年(\d{1,2})月份?及以后/);
    if (afterMonth) {
      return { after: parseDate(`${afterMonth[1]}-${afterMonth[2]}-01`) };
    }
    const since = text.match(/(\d{4})年(\d{1,2})月以来/);
    if (since) {
      return { after: parseDate(`${since[1]}-${since[2]}-01`) };
    }
    const yearOnly = text.match(/至少在(\d{4})年/);
    if (yearOnly) {
      return { after: parseDate(`${yearOnly[1]}-01-01`) };
    }
    const yearRange = text.match(/(\d{4})年\s*[-~至]\s*(\d{4})年提交/);
    if (yearRange) {
      return {
        after: parseDate(`${yearRange[1]}-01-01`),
        before: parseDate(`${yearRange[2]}-12-31`),
      };
    }
    return {};
  }

  function inDateRange(vulnDate, range) {
    const d = parseDate(vulnDate);
    if (range.after && d < range.after) return false;
    if (range.before && d > range.before) return false;
    return true;
  }

  function filterVulns(vulns, source, dateRange, opts) {
    return vulns.filter(
      (v) =>
        isCountableVuln(v, opts) &&
        schoolMatches(v.title, source) &&
        inDateRange(v.date, dateRange)
    );
  }

  function countBySeverity(vulns, minLevel) {
    return vulns.filter((v) => v.severityLevel >= minLevel).length;
  }

  function parseOrRules(text) {
    const rules = [];
    const orParts = text.split(/或|\/|\|/);
    for (const part of orParts) {
      const high = part.match(/(\d+)\s*个?.*?高危/);
      if (high) {
        rules.push({ type: "count", minLevel: 3, count: parseInt(high[1], 10) });
        continue;
      }
      const mid = part.match(/(\d+)\s*个?.*?中危/);
      if (mid) {
        rules.push({ type: "count", minLevel: 2, count: parseInt(mid[1], 10) });
        continue;
      }
      const low = part.match(/(\d+)\s*个?.*?低危/);
      if (low) {
        rules.push({ type: "count", minLevel: 1, count: parseInt(low[1], 10) });
        continue;
      }
    }
    return rules;
  }

  function parseRequirement(description, source) {
    const text = description.replace(/\s+/g, " ");
    const dateRange = extractDateRange(text);
    const orRules = parseOrRules(text);
    if (orRules.length > 1) {
      return { type: "or", rules: orRules, dateRange, source, raw: text };
    }
    const tongji = text.match(/(\d+)个低危/);
    const tongjiMid = text.match(/(\d+)个中危/);
    if (tongji && tongjiMid && text.includes("或")) {
      return {
        type: "or",
        rules: [
          { type: "count", minLevel: 2, count: parseInt(tongjiMid[1], 10) },
          { type: "count", minLevel: 1, count: parseInt(tongji[1], 10), note: "需不同系统" },
        ],
        dateRange,
        source,
        raw: text,
      };
    }
    const patterns = [
      { re: /至少提交过\s*(\d+)\s*个.*?高危.*?或.*?(\d+)\s*个.*?中危/, orHigh: 3, orMid: 2 },
      { re: /至少.*?(\d+)\s*个.*?严重/, level: 4 },
      { re: /至少.*?(\d+)\s*个.*?高危/, level: 3 },
      { re: /提交过\s*(\d+)\s*个.*?高危/, level: 3 },
      { re: /提交过\s*(\d+)\s*个.*?中危/, level: 2 },
      { re: /(\d+)\s*个.*?中危.*?或以上/, level: 2 },
      { re: /(\d+)\s*个.*?高危.*?或以上/, level: 3 },
      { re: /(\d+)\s*个.*?严重.*?或以上/, level: 4 },
      { re: /(\d+)\s*个.*?低危.*?及以上/, level: 1 },
      { re: /(\d+)\s*个.*?中危/, level: 2 },
      { re: /(\d+)\s*个.*?高危/, level: 3 },
      { re: /(\d+)\s*个.*?低危/, level: 1 },
    ];
    for (const p of patterns) {
      const m = text.match(p.re);
      if (m && p.orHigh) {
        return {
          type: "or",
          rules: [
            { type: "count", minLevel: p.orHigh, count: parseInt(m[1], 10) },
            { type: "count", minLevel: p.orMid, count: parseInt(m[2], 10) },
          ],
          dateRange,
          source,
          raw: text,
        };
      }
      if (m) {
        return {
          type: "count",
          minLevel: p.level,
          count: parseInt(m[1], 10),
          dateRange,
          source,
          raw: text,
        };
      }
    }
    return { type: "unknown", minLevel: 2, count: 1, dateRange, source, raw: text };
  }

  function pickMatchingVulns(vulns, minLevel, count) {
    return [...vulns]
      .filter((v) => v.severityLevel >= minLevel)
      .sort((a, b) => b.severityLevel - a.severityLevel || b.date.localeCompare(a.date))
      .slice(0, count);
  }

  function evaluateRule(rule, vulns, opts) {
    if (rule.type === "or") {
      for (const sub of rule.rules) {
        const matched = evaluateRule(
          { ...sub, dateRange: rule.dateRange, source: rule.source },
          vulns,
          opts
        );
        if (matched.eligible) return matched;
      }
      return { eligible: false, reason: "未满足任一兑换条件", matchedVulns: [] };
    }
    const filtered = filterVulns(vulns, rule.source, rule.dateRange, opts);
    const count = countBySeverity(filtered, rule.minLevel);
    if (count >= rule.count) {
      const matchedVulns = pickMatchingVulns(filtered, rule.minLevel, rule.count);
      const levelName = Object.keys(SEVERITY_MAP).find((k) => SEVERITY_MAP[k] === rule.minLevel);
      let reason = `满足：${rule.count} 个${levelName}及以上漏洞`;
      if (rule.note) reason += `（${rule.note}，请自行核对）`;
      return { eligible: true, reason, matchedVulns };
    }
    const levelName = Object.keys(SEVERITY_MAP).find((k) => SEVERITY_MAP[k] === rule.minLevel);
    const dateHint = rule.dateRange.after ? `（${rule.dateRange.after.getFullYear()}年后）` : "";
    return {
      eligible: false,
      reason: `需要 ${rule.source} ${rule.count} 个${levelName}及以上漏洞${dateHint}，当前仅 ${count} 个`,
      matchedVulns: filtered,
    };
  }

  function canRedeemLimit(limitStr) {
    if (!limitStr) return true;
    const m = limitStr.match(/(\d+)\/(\d+)/);
    if (!m) return true;
    return parseInt(m[1], 10) < parseInt(m[2], 10);
  }

  function matchCertificates(vulns, gifts, opts) {
    const o = normalizeMatchOptions(opts);
    const results = [];
    for (const gift of gifts) {
      const school = resolveGiftSchool(gift);
      const rule = parseRequirement(gift.description, school);
      const evalResult = evaluateRule(rule, vulns, o);
      const hasStock = gift.stock > 0;
      const withinLimit = canRedeemLimit(gift.limit);
      const eligible = evalResult.eligible && hasStock && withinLimit;
      const preview =
        eligible &&
        evalResult.matchedVulns?.length > 0 &&
        evalResult.matchedVulns.every((v) => !v.approved);
      const issues = [];
      if (!evalResult.eligible) issues.push(evalResult.reason);
      if (!hasStock) issues.push("库存不足");
      if (!withinLimit) issues.push(`已达兑换上限（${gift.limit}）`);
      const relatedVulns = vulns.filter((v) => {
        if (o.excludeFailed && isFailedVuln(v)) return false;
        return schoolMatches(v.title, school);
      });
      const statusNote = describeCertStatus(
        school,
        evalResult,
        relatedVulns,
        eligible,
        issues,
        o
      );
      results.push({
        ...gift,
        eligible,
        preview,
        reason: evalResult.reason,
        statusNote,
        issues,
        matchedVulns: evalResult.matchedVulns,
        relatedVulns,
        rule,
      });
    }
    results.sort((a, b) => (a.eligible === b.eligible ? 0 : a.eligible ? -1 : 1));
    return results;
  }

  g.EdusrcMatcher = {
    matchCertificates,
    normalizeSchool,
    schoolMatches,
    resolveGiftSchool,
    buildScanHints,
    describeCertStatus,
    normalizeMatchOptions,
    isCountableVuln,
    DEFAULT_MATCH_OPTIONS,
  };
})(globalThis);

(function (g) {
  if (g.__EDUSRC_ENGINE_V__ !== 7 || !g.EdusrcParser) return;

  const BASE = "https://src.sjtu.edu.cn";
  const GIFT_CATALOG_KEY = "edusrc_gift_catalog_v2";
  const GIFT_CATALOG_TTL = 6 * 60 * 60 * 1000;
  const { isLoginPage, extractUserId, parseVulnTable, getMaxPage, parseGiftList, parseGiftDetail } =
    g.EdusrcParser;

  async function fetchPage(path) {
    const url = path.startsWith("http") ? path : `${BASE}${path}`;
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), 30000);
    try {
      const res = await fetch(url, {
        credentials: "include",
        headers: { Accept: "text/html" },
        signal: controller.signal,
      });
      if (!res.ok) throw new Error(`请求失败 ${res.status}`);
      return res.text();
    } catch (err) {
      if (err.name === "AbortError") throw new Error("请求超时，请检查网络或刷新页面重试");
      throw err;
    } finally {
      clearTimeout(timer);
    }
  }

  async function mapPool(items, concurrency, fn) {
    const results = new Array(items.length);
    let next = 0;
    async function worker() {
      while (next < items.length) {
        const i = next++;
        results[i] = await fn(items[i], i);
      }
    }
    await Promise.all(Array.from({ length: Math.min(concurrency, items.length || 1) }, worker));
    return results;
  }

  async function fetchPagesParallel(maxPage, pagePathFn, onPageDone) {
    if (maxPage <= 1) return [];
    const pages = Array.from({ length: maxPage - 1 }, (_, i) => i + 2);
    let done = 0;
    return mapPool(pages, 8, async (page) => {
      const html = await fetchPage(pagePathFn(page));
      done++;
      onPageDone?.(done, pages.length);
      return html;
    });
  }

  async function getCatalogCache() {
    const data = await chrome.storage.local.get(GIFT_CATALOG_KEY);
    const cached = data[GIFT_CATALOG_KEY];
    if (!cached || Date.now() - cached.updatedAt > GIFT_CATALOG_TTL) return null;
    return cached.gifts;
  }

  async function saveCatalogCache(gifts) {
    await chrome.storage.local.set({ [GIFT_CATALOG_KEY]: { gifts, updatedAt: Date.now() } });
  }

  function mergeGiftListWithCatalog(giftList, catalog) {
    const map = new Map(catalog.map((item) => [item.id, item]));
    return giftList.map((item) => {
      const cached = map.get(item.id);
      if (!cached) return item;
      return { ...cached, name: item.name || cached.name, stock: item.stock, price: item.price, url: item.url };
    });
  }

  function createScanProgress(onProgress) {
    let vulnPct = 0;
    let giftPct = 0;
    const emit = (text, percentOverride) => {
      onProgress?.({
        text,
        percent: percentOverride ?? Math.min(99, Math.round(vulnPct * 0.45 + giftPct * 0.5)),
        running: true,
      });
    };
    return {
      vuln(text, pct) { vulnPct = pct; emit(text); },
      gift(text, pct) { giftPct = pct; emit(text); },
      matching(text) { onProgress?.({ text, percent: 96, running: true }); },
      done(text) { onProgress?.({ text: text || "完成", percent: 100, running: false }); },
    };
  }

  async function fetchAllVulns(progress) {
    progress.vuln("获取漏洞列表…", 5);
    const basePath = "/profile/post/";
    const first = await fetchPage(basePath);
    if (isLoginPage(first)) throw new Error("NOT_LOGGED_IN");
    const userId = extractUserId(first) || "self";
    let vulns = parseVulnTable(first);
    const seen = new Set(vulns.map((v) => v.id));
    const maxPage = getMaxPage(first);

    for (let page = 2; page <= maxPage; page++) {
      progress.vuln(`漏洞列表 第 ${page}/${maxPage} 页`, 10 + Math.round(((page - 1) / maxPage) * 35));
      const html = await fetchPage(`${basePath}?page=${page}`);
      for (const v of parseVulnTable(html)) {
        if (!seen.has(v.id)) {
          seen.add(v.id);
          vulns.push(v);
        }
      }
    }

    for (let page = maxPage + 1; page <= maxPage + 5; page++) {
      const html = await fetchPage(`${basePath}?page=${page}`);
      const batch = parseVulnTable(html);
      if (!batch.length) break;
      let added = 0;
      for (const v of batch) {
        if (!seen.has(v.id)) {
          seen.add(v.id);
          vulns.push(v);
          added++;
        }
      }
      if (!added) break;
    }

    progress.vuln(`已加载 ${vulns.length} 条漏洞（${vulns.filter((v) => v.approved).length} 条已通过）`, 100);
    return { vulns, userId };
  }

  async function fetchAllGifts(progress) {
    progress.gift("获取礼品列表…", 5);
    const basePath = "/gift/?gift_type=certificate";
    const first = await fetchPage(basePath);
    let gifts = parseGiftList(first);
    const seen = new Set(gifts.map((g) => g.id));
    const maxPage = getMaxPage(first);

    for (let page = 2; page <= maxPage; page++) {
      progress.gift(`证书列表 第 ${page}/${maxPage} 页`, 5 + Math.round(((page - 1) / maxPage) * 25));
      const html = await fetchPage(`${basePath}&page=${page}`);
      for (const g of parseGiftList(html)) {
        if (!seen.has(g.id)) {
          seen.add(g.id);
          gifts.push(g);
        }
      }
    }

    for (let page = maxPage + 1; page <= maxPage + 5; page++) {
      const html = await fetchPage(`${basePath}&page=${page}`);
      const batch = parseGiftList(html);
      if (!batch.length) break;
      let added = 0;
      for (const g of batch) {
        if (!seen.has(g.id)) {
          seen.add(g.id);
          gifts.push(g);
          added++;
        }
      }
      if (!added) break;
    }

    const pages = maxPage > 1 ? maxPage : Math.ceil(gifts.length / 36) || 1;
    progress.gift(`已加载 ${gifts.length} 个证书（共 ${pages} 页）`, 30);
    return { gifts, giftPages: pages };
  }

  async function enrichGiftsParallel(gifts, progress) {
    let done = 0;
    const total = gifts.length;
    return mapPool(gifts, 20, async (item) => {
      try {
        const html = await fetchPage(`/gift/${item.id}/`);
        return { ...item, ...parseGiftDetail(html) };
      } catch {
        return item;
      } finally {
        done++;
        if (done === total || done % 5 === 0) {
          progress.gift(`解析证书 ${done}/${total}`, 30 + Math.round((done / total) * 70));
        }
      }
    });
  }

  async function getEnrichedGifts(progress) {
    const cached = await getCatalogCache();
    const { gifts: giftList, giftPages } = await fetchAllGifts(progress);
    const listIds = giftList.map((g) => g.id).sort().join(",");
    const cachedIds = cached?.map((g) => g.id).sort().join(",");
    if (cached?.length && listIds === cachedIds) {
      progress.gift(`证书规则命中缓存（${giftList.length} 个）`, 100);
      return { gifts: mergeGiftListWithCatalog(giftList, cached), giftPages };
    }
    const enriched = await enrichGiftsParallel(giftList, progress);
    await saveCatalogCache(enriched);
    progress.gift(`已解析 ${enriched.length} 个证书`, 100);
    return { gifts: enriched, giftPages };
  }

  function stripGiftSnapshot(r) {
    const {
      eligible,
      preview,
      reason,
      statusNote,
      issues,
      matchedVulns,
      relatedVulns,
      rule,
      ...gift
    } = r;
    return gift;
  }

  function rematchScan(scan, options) {
    const opts = g.EdusrcMatcher.normalizeMatchOptions(options || scan.matchOptions);
    const gifts = scan.giftSnapshots || (scan.results || []).map(stripGiftSnapshot);
    const vulns = scan.vulns || [];
    const results = g.EdusrcMatcher.matchCertificates(vulns, gifts, opts);
    const hints = g.EdusrcMatcher.buildScanHints(vulns, gifts, opts);
    return {
      ...scan,
      results,
      hints,
      matchOptions: opts,
      countableCount: vulns.filter((v) => g.EdusrcMatcher.isCountableVuln(v, opts)).length,
      approvedCount: vulns.filter((v) => v.approved).length,
    };
  }

  async function runScan(onProgress, options) {
    const opts = g.EdusrcMatcher.normalizeMatchOptions(options);
    const progress = createScanProgress(onProgress);
    progress.vuln("开始扫描…", 0);
    progress.gift("准备加载证书…", 0);
    const [{ vulns, userId }, { gifts, giftPages }] = await Promise.all([
      fetchAllVulns(progress),
      getEnrichedGifts(progress),
    ]);
    progress.matching("匹配可兑换证书…");
    const results = g.EdusrcMatcher.matchCertificates(vulns, gifts, opts);
    const hints = g.EdusrcMatcher.buildScanHints(vulns, gifts, opts);
    progress.done("扫描完成");
    return {
      userId,
      vulnCount: vulns.length,
      approvedCount: vulns.filter((v) => v.approved).length,
      countableCount: vulns.filter((v) => g.EdusrcMatcher.isCountableVuln(v, opts)).length,
      giftCount: gifts.length,
      giftPages,
      vulns,
      giftSnapshots: gifts,
      matchOptions: opts,
      results,
      hints,
      scannedAt: Date.now(),
      engineVersion: g.__EDUSRC_ENGINE_V__,
    };
  }

  g.EdusrcApi = { runScan, rematchScan, fetchPage, isLoginPage };
})(globalThis);
