(function (g) {
  const ENGINE_VERSION = 14;
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

  function extractCoins(html) {
    if (!html) return null;

    const doc = parseHtml(html);
    let found = null;

    doc.querySelectorAll(".am-g").forEach((row) => {
      row.querySelectorAll(".am-u-sm-2, .am-u-sm-3").forEach((label) => {
        if (!/^金币$/.test(label.textContent.trim())) return;
        const value =
          label.nextElementSibling ||
          row.querySelector(".am-u-sm-10, .am-u-sm-9, .am-u-sm-4");
        if (!value || value === label) return;
        const n = parseInt(value.textContent.match(/(\d+)/)?.[1], 10);
        if (!Number.isNaN(n)) found = n;
      });
    });
    if (found !== null) return found;

    doc.querySelectorAll("tr").forEach((row) => {
      const cells = row.querySelectorAll("td, th");
      if (cells.length < 2 || !/金币/.test(cells[0].textContent)) return;
      const n = parseInt(cells[1].textContent.match(/(\d+)/)?.[1], 10);
      if (!Number.isNaN(n)) found = n;
    });
    if (found !== null) return found;

    const patterns = [
      /(?:我的|当前|剩余)?金币[：:\s]*(\d+)/,
      /金币余额[：:\s]*(\d+)/,
      /拥有\s*(\d+)\s*金币/,
    ];
    for (const re of patterns) {
      const m = html.match(re);
      if (m) return parseInt(m[1], 10);
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

  function extractPublicProfileMeta(html) {
    const doc = parseHtml(html);
    let nickname = "";
    const titleEl = doc.querySelector(".am-panel-title");
    if (titleEl) nickname = titleEl.textContent.replace(/\s*的个人中心\s*$/, "").trim();
    if (!nickname) {
      const bq = doc.querySelector("blockquote");
      if (bq) nickname = bq.textContent.trim();
    }
    let rank = null;
    const rankMatch = html.match(/Rank[：:\s]*(\d+)/);
    if (rankMatch) rank = parseInt(rankMatch[1], 10);
    let approvedCount = null;
    const ap = html.match(/已审核通过漏洞数量[：:\s]*(\d+)/);
    if (ap) approvedCount = parseInt(ap[1], 10);
    let totalCount = null;
    const tp = html.match(/总提交漏洞数量[：:\s]*(\d+)/);
    if (tp) totalCount = parseInt(tp[1], 10);
    return { nickname, rank, approvedCount, totalCount };
  }

  function isProfileNotFound(html) {
    return (
      /<title>\s*Not Found/i.test(html) ||
      /<h1>\s*Not Found/i.test(html) ||
      /was not found on this server/i.test(html)
    );
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
    extractCoins,
    extractPublicProfileMeta,
    isProfileNotFound,
    parseVulnTable,
    getMaxPage,
    parseGiftList,
    parseGiftDetail,
  };
})(globalThis);

(function (g) {
  if (g.__EDUSRC_ENGINE_V__ !== 14 || !g.EdusrcParser) return;

  const { SEVERITY_MAP } = g.EdusrcParser;

  /** 校名结尾（用于识别「仍是学校称谓」） */
  const SCHOOL_TAIL_RE = /(?:职业技术学院|职业学院|高等专科学校|师范专科学校|专科学校|大学|学院|学校|分校)$/;

  /**
   * 母体高校下的内设院系/部门（匹配母体证书时视为同一学校）
   * 不含独立学院专名（成贤/金陵等）
   */
  const INTERNAL_UNIT_RE =
    /^(?:本部|主校区|东校区|西校区|南校区|北校区|新校区|老校区|[\u4e00-\u9fff]{1,8}校区|研究生院|研究生学院|继续教育学院|网络教育学院|成人教育学院|远程教育学院|国际教育学院|国际学院|马克思主义学院|体育学院|体育部|人文学院|文学院|理学院|工学院|商学院|管理学院|经济学院|经济管理学院|法学院|医学院|护理学院|药学院|公共卫生学院|软件学院|计算机学院|信息学院|信息工程学院|电子信息学院|外国语学院|外语学院|艺术学院|音乐学院|美术学院|新闻学院|传播学院|教育学院|化学学院|物理学院|数学学院|生命科学学院|环境学院|材料学院|自动化学院|机械学院|土木学院|建筑学院|交通学院|航空航天学院|海洋学院|农学院|林学院|网络与信息中心|现代教育技术中心|信息化(?:办公室|中心)|信息中心|网络中心|图书馆|档案馆|校医院|后勤(?:集团|处)?|党委办公室|校长办公室|团委)$/;

  /** 明确另一法人/另一报送主体 */
  const DISTINCT_UNIT_RE =
    /^(?:附属(?:中学|小学|幼儿园|中小学|学校)|独立学院|职业技术学院|职业学院|高等专科学校|师范专科学校|专科学校|分校|合作办学|联合学院)/;

  /**
   * 无歧义别名 → 规范全称（故意不做「东大/南大/长大」等易撞车简称）
   * 一侧是别名、一侧是全称时仍可匹配
   */
  const SCHOOL_ALIAS_TO_FULL = {
    清华: "清华大学",
    北大: "北京大学",
    复旦: "复旦大学",
    上交: "上海交通大学",
    上海交大: "上海交通大学",
    交大闵行: "上海交通大学",
    浙大: "浙江大学",
    中科大: "中国科学技术大学",
    中国科大: "中国科学技术大学",
    国科大: "中国科学院大学",
    华科: "华中科技大学",
    华中科大: "华中科技大学",
    人大: "中国人民大学",
    北师大: "北京师范大学",
    南开: "南开大学",
    同济: "同济大学",
    西交: "西安交通大学",
    西安交大: "西安交通大学",
    哈工大: "哈尔滨工业大学",
    中山大学: "中山大学",
    中大: "中山大学",
    厦大: "厦门大学",
    武大: "武汉大学",
    川大: "四川大学",
    电子科大: "电子科技大学",
    成电: "电子科技大学",
    北航: "北京航空航天大学",
    北邮: "北京邮电大学",
    北理: "北京理工大学",
    华师: "华东师范大学",
    华师大: "华东师范大学",
    上财: "上海财经大学",
    央财: "中央财经大学",
    对外经贸: "对外经济贸易大学",
    贸大: "对外经济贸易大学",
  };

  function normalizeSchool(name) {
    if (!name) return "";
    return String(name)
      .replace(/[\u200b\u200c\u200d\ufeff]/g, "")
      .replace(/[（(].*?[）)]/g, "")
      .replace(/版漏洞报送证书.*$/g, "")
      .replace(/漏洞报送证书.*$/g, "")
      .replace(/原创漏洞证书[-\s]*/g, "")
      .replace(/礼品[-\s]*/g, "")
      .replace(/(?:的)?(?:漏洞|安全漏洞).*$/g, "")
      .replace(/\d{4}\s*年?/g, "")
      .replace(/[·・•．.、，,\s_/|－—–-]+/g, "")
      .replace(/[東东]/g, "东")
      .replace(/國/g, "国")
      .replace(/學/g, "学")
      .replace(/灣/g, "湾")
      .replace(/門/g, "门")
      .replace(/見/g, "见")
      .replace(/務/g, "务")
      .replace(/業/g, "业")
      .replace(/義/g, "义")
      .replace(/漢/g, "汉")
      .replace(/華/g, "华")
      .replace(/師/g, "师")
      .replace(/範/g, "范")
      .replace(/醫/g, "医")
      .replace(/術/g, "术")
      .replace(/電/g, "电")
      .replace(/經/g, "经")
      .replace(/濟/g, "济")
      .replace(/態/g, "态")
      .replace(/報/g, "报")
      .replace(/大學/g, "大学")
      .replace(/學院/g, "学院")
      .replace(/學校/g, "学校")
      .trim();
  }

  /** 去掉内设院系/校区等同校尾巴，得到可用于比对的主体校名 */
  function stripSameOrgTail(name) {
    let s = normalizeSchool(name);
    if (!s) return "";
    for (let i = 0; i < 3; i++) {
      const m = s.match(/^(.*?(?:职业技术学院|职业学院|大学|学院|学校))(.+)$/);
      if (!m) break;
      const [, head, rest] = m;
      if (INTERNAL_UNIT_RE.test(rest)) {
        s = head;
        continue;
      }
      break;
    }
    return s;
  }

  function canonicalSchool(name) {
    const core = stripSameOrgTail(name);
    if (!core) return "";
    return SCHOOL_ALIAS_TO_FULL[core] || core;
  }

  function aliasVariants(name) {
    const core = stripSameOrgTail(name);
    const full = canonicalSchool(name);
    const set = new Set([core, full].filter(Boolean));
    for (const [alias, target] of Object.entries(SCHOOL_ALIAS_TO_FULL)) {
      if (target === full || target === core) set.add(alias);
    }
    return set;
  }

  /**
   * longer 以 shorter 为前缀，且剩余部分像「另一所学校」
   * 例：东南大学 + 成贤学院 → true；东南大学 + 软件学院 → false
   */
  function isDistinctSchoolExtension(shorter, longer) {
    if (!shorter || !longer || longer === shorter) return false;
    if (!longer.startsWith(shorter)) return false;
    const rest = longer.slice(shorter.length);
    if (!rest) return false;
    if (INTERNAL_UNIT_RE.test(rest)) return false;
    if (DISTINCT_UNIT_RE.test(rest)) return true;
    // 大学 + 专名学院 → 独立学院（成贤学院、金陵学院、嘉庚学院…）
    // 允许后缀还有系统描述：成贤学院某系统
    const indieCollege = rest.match(/^([\u4e00-\u9fff]{1,10}学院)/);
    if (
      /大学$/.test(shorter) &&
      indieCollege &&
      !INTERNAL_UNIT_RE.test(indieCollege[1])
    ) {
      return true;
    }
    // 剩余整段仍是学校称谓，且不是内设单位
    if (SCHOOL_TAIL_RE.test(rest) && !INTERNAL_UNIT_RE.test(rest)) return true;
    // 更长短名整体是学校，且后缀以汉字延续校名
    if (
      SCHOOL_TAIL_RE.test(longer) &&
      /^[\u4e00-\u9fff]/.test(rest) &&
      !INTERNAL_UNIT_RE.test(rest) &&
      rest.length >= 2
    ) {
      return true;
    }
    return false;
  }

  /**
   * needle 出现在 haystack 的 index 处是否像「完整校名边界」
   * 拒绝：华北[电力大学]、中国[科学技术大学] 这类中嵌
   */
  function hasSchoolBoundary(haystack, needle, index) {
    if (index < 0) return false;
    const before = haystack.slice(0, index);
    const after = haystack.slice(index + needle.length);

    if (before && /[\u4e00-\u9fffA-Za-z0-9]$/.test(before)) return false;

    if (!after) return true;
    if (INTERNAL_UNIT_RE.test(after)) return true;
    if (/^(?:存在|系统|平台|网站|门户|首页|登录|管理|漏洞|安全|的)/.test(after)) return true;
    if (isDistinctSchoolExtension(needle, needle + after)) return false;
    if (SCHOOL_TAIL_RE.test(haystack) && /^[\u4e00-\u9fff]/.test(after)) {
      return INTERNAL_UNIT_RE.test(after);
    }
    return true;
  }

  function containsSchoolName(haystack, needle) {
    if (!haystack || !needle) return false;
    if (needle.length < 2) return false;
    // 过短且非别名的片段不允许 includes（防「大学」「学院」）
    if (needle.length < 4 && !SCHOOL_ALIAS_TO_FULL[needle] && !SCHOOL_TAIL_RE.test(needle)) {
      return false;
    }
    let from = 0;
    while (from <= haystack.length - needle.length) {
      const idx = haystack.indexOf(needle, from);
      if (idx === -1) return false;
      if (hasSchoolBoundary(haystack, needle, idx)) return true;
      from = idx + 1;
    }
    return false;
  }

  function schoolMatches(vulnTitle, source) {
    if (!source) return false;
    const rawTitle = stripSameOrgTail(vulnTitle);
    const rawSrc = stripSameOrgTail(source);
    if (!rawTitle || !rawSrc) return false;

    const title = canonicalSchool(vulnTitle);
    const src = canonicalSchool(source);
    if (!title || !src) return false;

    if (title === src) return true;

    // 别名集合相交（清华 ↔ 清华大学）
    const titleAliases = aliasVariants(vulnTitle);
    const srcAliases = aliasVariants(source);
    for (const a of titleAliases) {
      if (srcAliases.has(a)) return true;
    }

    // 母体 ↔ 独立学院 / 附属中小学 / 分校 等，双向拒绝
    if (isDistinctSchoolExtension(src, title) || isDistinctSchoolExtension(title, src)) {
      return false;
    }
    if (
      isDistinctSchoolExtension(rawSrc, rawTitle) ||
      isDistinctSchoolExtension(rawTitle, rawSrc)
    ) {
      return false;
    }

    // 边界安全的包含（漏洞标题里带校名+系统描述，或来源略短）
    if (containsSchoolName(title, src)) return true;
    if (src.length >= 4 && containsSchoolName(src, title)) return true;

    return false;
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

  const DEFAULT_MATCH_OPTIONS = { excludeFailed: true, includePending: false, publicProfile: false };

  function normalizeMatchOptions(opts) {
    return {
      excludeFailed: opts?.excludeFailed !== false,
      includePending: !!opts?.includePending,
      publicProfile: !!opts?.publicProfile,
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
    const fromDay = text.match(/(\d{4})年(\d{1,2})月(\d{1,2})日起/);
    if (fromDay) {
      return { after: parseDate(`${fromDay[1]}-${fromDay[2]}-${fromDay[3]}`) };
    }
    const afterDay = text.match(/(\d{4})年(\d{1,2})月(\d{1,2})日后/);
    if (afterDay) {
      return { after: parseDate(`${afterDay[1]}-${afterDay[2]}-${afterDay[3]}`) };
    }
    const afterMonth = text.match(/(\d{4})年(\d{1,2})月份?及以后/);
    if (afterMonth) {
      return { after: parseDate(`${afterMonth[1]}-${afterMonth[2]}-01`) };
    }
    const afterMonthShort = text.match(/(\d{4})年(\d{1,2})月后/);
    if (afterMonthShort) {
      return { after: parseDate(`${afterMonthShort[1]}-${afterMonthShort[2]}-01`) };
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
    const text = String(description || "").replace(/\s+/g, " ");
    const dateRange = extractDateRange(text);
    const orRules = parseOrRules(text);
    if (orRules.length > 1) {
      return { type: "or", rules: orRules, dateRange, source, raw: text };
    }
    const levelMap = { 严重: 4, 高危: 3, 中危: 2, 低危: 1 };
    const oneSeverity = text.match(/至少.*?提交(?:过)?(?:一个|1\s*个).*?(严重|高危|中危|低危)/);
    if (oneSeverity) {
      return {
        type: "count",
        minLevel: levelMap[oneSeverity[1]] || 2,
        count: 1,
        dateRange,
        source,
        raw: text,
      };
    }
    const andAbove = text.match(/提交(\d+)个及以上/);
    if (andAbove) {
      let level = 2;
      if (/低危/.test(text)) level = 1;
      else if (/严重/.test(text)) level = 4;
      else if (/高危/.test(text)) level = 3;
      return {
        type: "count",
        minLevel: level,
        count: parseInt(andAbove[1], 10),
        dateRange,
        source,
        raw: text,
      };
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

  function requiresPriorCert(description) {
    return /已获得.*证书|已获.*漏洞报送证书|已获我校/.test(description || "");
  }

  function checkPriorCert(gift, certResults, opts) {
    if (!requiresPriorCert(gift.description)) return { ok: true };
    if (normalizeMatchOptions(opts).publicProfile) {
      return { ok: false, reason: "需已获漏洞报送证书（公开页无法验证）", unverifiable: true };
    }
    const school = resolveGiftSchool(gift);
    const relatedCerts = (certResults || []).filter((r) => {
      const cs = resolveGiftSchool(r);
      return cs && schoolMatches(school, cs);
    });
    if (!relatedCerts.length) {
      return { ok: false, reason: "需先获得对应学校漏洞报送证书" };
    }
    if (relatedCerts.some((r) => !canRedeemLimit(r.limit))) {
      return { ok: true };
    }
    if (relatedCerts.some((r) => r.eligible)) {
      return { ok: false, reason: "需先兑换并获得漏洞报送证书" };
    }
    return { ok: false, reason: "需先获得对应学校漏洞报送证书" };
  }

  function isVendorGift(gift) {
    const text = `${gift.source || ""}${gift.description || ""}`;
    return /公司|Panabit|开发方|开发商|厂商/.test(text);
  }

  function needsManualCheck(description) {
    return /(\d+)\s*家(?:学校|高校)|开发方|开发商请选择|不同系统.*或/.test(description || "");
  }

  function describeTangibleStatus(gift, evalResult, eligible, issues, opts) {
    if (eligible) {
      const pendingOnly =
        evalResult.matchedVulns?.length > 0 &&
        evalResult.matchedVulns.every((v) => !v.approved);
      const base = `${evalResult.reason} · ${gift.price} 金币`;
      if (pendingOnly && normalizeMatchOptions(opts).includePending) {
        return `${base}（待审核，通过后正式可兑换）`;
      }
      return base;
    }
    if (needsManualCheck(gift.description)) {
      const manual = "含额外人工审核条件，请阅读礼物描述";
      return issues.length ? `${issues.join("；")}；${manual}` : manual;
    }
    return issues.join("；") || evalResult.reason;
  }

  function matchTangibleGifts(coins, gifts, vulns, opts, certResults) {
    const o = normalizeMatchOptions(opts);
    const results = [];
    for (const gift of gifts) {
      const school = resolveGiftSchool(gift);
      const rule = parseRequirement(gift.description, school);
      const evalResult = evaluateRule(rule, vulns || [], o);
      const hasStock = gift.stock > 0;
      const withinLimit = canRedeemLimit(gift.limit);
      const canAfford = coins !== null && coins >= gift.price;
      const certCheck = checkPriorCert(gift, certResults, o);

      const issues = [];
      if (!evalResult.eligible) issues.push(evalResult.reason);
      if (!certCheck.ok) issues.push(certCheck.reason);
      if (!hasStock) issues.push("库存不足");
      if (!withinLimit) issues.push(`已达兑换上限（${gift.limit}）`);
      if (coins === null) issues.push("未能读取金币余额");
      else if (!canAfford) issues.push(`金币不足（需 ${gift.price}，当前 ${coins}）`);
      if (isVendorGift(gift) && !evalResult.eligible && evalResult.matchedVulns?.length === 0) {
        issues.push("开发方/厂商类礼物需自行核对漏洞归属");
      }

      const eligible =
        evalResult.eligible &&
        hasStock &&
        withinLimit &&
        canAfford &&
        certCheck.ok &&
        !certCheck.unverifiable;
      const preview =
        eligible &&
        evalResult.matchedVulns?.length > 0 &&
        evalResult.matchedVulns.every((v) => !v.approved);

      const relatedVulns = (vulns || []).filter((v) => {
        if (o.excludeFailed && isFailedVuln(v)) return false;
        return schoolMatches(v.title, school);
      });

      const statusNote = describeTangibleStatus(gift, evalResult, eligible, issues, o);

      results.push({
        ...gift,
        giftKind: "tangible",
        eligible,
        preview,
        reason: evalResult.reason,
        statusNote,
        issues,
        matchedVulns: evalResult.matchedVulns,
        relatedVulns,
        rule,
        vendorGift: isVendorGift(gift),
      });
    }
    results.sort((a, b) => {
      if (a.eligible !== b.eligible) return a.eligible ? -1 : 1;
      if (a.preview !== b.preview) return a.preview ? 1 : -1;
      return a.price - b.price;
    });
    return results;
  }

  g.EdusrcMatcher = {
    matchCertificates,
    matchTangibleGifts,
    normalizeSchool,
    stripSameOrgTail,
    canonicalSchool,
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
  if (g.__EDUSRC_ENGINE_V__ !== 14 || !g.EdusrcParser) return;

  const BASE = "https://src.sjtu.edu.cn";
  const GIFT_CATALOG_KEY = "edusrc_gift_catalog_v2";
  const TANGIBLE_CATALOG_KEY = "edusrc_tangible_catalog_v2";
  const GIFT_CATALOG_TTL = 6 * 60 * 60 * 1000;
  const { isLoginPage, extractUserId, extractCoins, extractPublicProfileMeta, isProfileNotFound, parseVulnTable, getMaxPage, parseGiftList, parseGiftDetail } =
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

  async function getCatalogCache(key = GIFT_CATALOG_KEY) {
    const data = await chrome.storage.local.get(key);
    const cached = data[key];
    if (!cached || Date.now() - cached.updatedAt > GIFT_CATALOG_TTL) return null;
    return cached.gifts;
  }

  async function saveCatalogCache(gifts, key = GIFT_CATALOG_KEY) {
    await chrome.storage.local.set({ [key]: { gifts, updatedAt: Date.now() } });
  }

  function isGiftRuleComplete(gift) {
    return !!(gift && (gift.description || gift.source));
  }

  function mergeGiftListWithCatalog(giftList, catalog) {
    const map = new Map(catalog.map((item) => [item.id, item]));
    return giftList.map((item) => {
      const cached = map.get(item.id);
      if (!cached || !isGiftRuleComplete(cached)) return item;
      return {
        ...cached,
        name: item.name || cached.name,
        stock: item.stock,
        price: item.price,
        url: item.url,
      };
    });
  }

  function createScanProgress(onProgress) {
    let vulnPct = 0;
    let giftPct = 0;
    let tangiblePct = 0;
    const emit = (text, percentOverride) => {
      onProgress?.({
        text,
        percent:
          percentOverride ??
          Math.min(99, Math.round(vulnPct * 0.35 + giftPct * 0.35 + tangiblePct * 0.25)),
        running: true,
      });
    };
    return {
      vuln(text, pct) { vulnPct = pct; emit(text); },
      gift(text, pct) { giftPct = pct; emit(text); },
      tangible(text, pct) { tangiblePct = pct; emit(text); },
      matching(text) { onProgress?.({ text, percent: 96, running: true }); },
      done(text) { onProgress?.({ text: text || "完成", percent: 100, running: false }); },
    };
  }

  async function resolveCoins(firstHtml, userId) {
    let coins = extractCoins(firstHtml);
    if (coins !== null) return coins;

    const paths = ["/profile/detail/"];
    if (userId && userId !== "self") paths.push(`/profile/${userId}/`);
    paths.push("/gift/?gift_type=tangible_gift");

    for (const path of paths) {
      try {
        coins = extractCoins(await fetchPage(path));
        if (coins !== null) return coins;
      } catch {
        /* try next */
      }
    }
    return null;
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
    const coins = await resolveCoins(first, userId);
    return { vulns, userId, coins };
  }

  async function fetchUserVulns(targetUserId, progress) {
    progress.vuln(`获取用户 ${targetUserId} 的公开漏洞…`, 5);
    const basePath = `/profile/${targetUserId}/`;
    const first = await fetchPage(basePath);
    if (isLoginPage(first)) throw new Error("NOT_LOGGED_IN");
    if (isProfileNotFound(first)) throw new Error("USER_NOT_FOUND");

    const meta = extractPublicProfileMeta(first);
    let vulns = parseVulnTable(first);
    const seen = new Set(vulns.map((v) => v.id));
    const maxPage = getMaxPage(first);

    for (let page = 2; page <= maxPage; page++) {
      progress.vuln(`公开漏洞 第 ${page}/${maxPage} 页`, 10 + Math.round(((page - 1) / maxPage) * 35));
      const html = await fetchPage(`${basePath}?page=${page}`);
      if (isProfileNotFound(html)) break;
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

    const approved = vulns.filter((v) => v.approved).length;
    progress.vuln(`已加载 ${vulns.length} 条公开漏洞（${approved} 条有 Rank）`, 100);
    const coins = meta.rank !== null ? meta.rank : null;
    return { vulns, userId: String(targetUserId), coins, meta, coinsEstimated: true };
  }

  async function fetchGiftListByType(giftType, label, report) {
    report(`获取${label}列表…`, 5);
    const basePath = `/gift/?gift_type=${giftType}`;
    const first = await fetchPage(basePath);
    let gifts = parseGiftList(first);
    const seen = new Set(gifts.map((g) => g.id));
    const maxPage = getMaxPage(first);

    for (let page = 2; page <= maxPage; page++) {
      report(`${label} 第 ${page}/${maxPage} 页`, 5 + Math.round(((page - 1) / maxPage) * 25));
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
    report(`已加载 ${gifts.length} 个${label}（共 ${pages} 页）`, 30);
    return { gifts, giftPages: pages };
  }

  async function fetchAllGifts(progress) {
    return fetchGiftListByType("certificate", "证书", (text, pct) => progress.gift(text, pct));
  }

  async function fetchAllTangibleGifts(progress) {
    return fetchGiftListByType("tangible_gift", "实物", (text, pct) => progress.tangible(text, pct));
  }

  async function enrichGiftsParallel(gifts, progress, label = "证书") {
    let done = 0;
    const total = gifts.length;
    const report = label === "实物"
      ? (text, pct) => progress.tangible(text, pct)
      : (text, pct) => progress.gift(text, pct);
    return mapPool(gifts, 20, async (item) => {
      try {
        const html = await fetchPage(`/gift/${item.id}/`);
        const detail = parseGiftDetail(html);
        return { ...item, ...detail };
      } catch {
        return item;
      } finally {
        done++;
        if (done === total || done % 5 === 0) {
          report(`解析${label} ${done}/${total}`, 30 + Math.round((done / total) * 70));
        }
      }
    });
  }

  async function ensureGiftRules(gifts, progress, label = "证书") {
    const incomplete = gifts.filter((g) => !isGiftRuleComplete(g));
    if (!incomplete.length) return gifts;
    const repaired = await enrichGiftsParallel(incomplete, progress, label);
    const map = new Map(repaired.map((g) => [g.id, g]));
    return gifts.map((g) => map.get(g.id) || g);
  }

  async function getEnrichedGifts(progress) {
    const cached = await getCatalogCache(GIFT_CATALOG_KEY);
    const { gifts: giftList, giftPages } = await fetchAllGifts(progress);
    const listIds = giftList.map((g) => g.id).sort().join(",");
    const cachedIds = cached?.map((g) => g.id).sort().join(",");
    let gifts;
    if (cached?.length && listIds === cachedIds) {
      gifts = mergeGiftListWithCatalog(giftList, cached);
      progress.gift(`证书规则命中缓存（${giftList.length} 个）`, 80);
    } else {
      gifts = await enrichGiftsParallel(giftList, progress, "证书");
    }
    gifts = await ensureGiftRules(gifts, progress, "证书");
    const complete = gifts.filter(isGiftRuleComplete);
    if (complete.length) await saveCatalogCache(complete, GIFT_CATALOG_KEY);
    progress.gift(`已解析 ${gifts.length} 个证书`, 100);
    return { gifts, giftPages };
  }

  async function getEnrichedTangibleGifts(progress) {
    const cached = await getCatalogCache(TANGIBLE_CATALOG_KEY);
    const { gifts: giftList, giftPages: tangiblePages } = await fetchAllTangibleGifts(progress);
    const listIds = giftList.map((g) => g.id).sort().join(",");
    const cachedIds = cached?.map((g) => g.id).sort().join(",");
    let gifts;
    if (cached?.length && listIds === cachedIds) {
      gifts = mergeGiftListWithCatalog(giftList, cached);
      progress.tangible(`实物规则命中缓存（${giftList.length} 个）`, 80);
    } else {
      gifts = await enrichGiftsParallel(giftList, progress, "实物");
    }
    gifts = await ensureGiftRules(gifts, progress, "实物");
    const complete = gifts.filter(isGiftRuleComplete);
    if (complete.length) await saveCatalogCache(complete, TANGIBLE_CATALOG_KEY);
    progress.tangible(`已解析 ${gifts.length} 个实物`, 100);
    return { gifts, tangiblePages };
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

  function stripTangibleSnapshot(r) {
    const {
      eligible,
      preview,
      reason,
      issues,
      statusNote,
      giftKind,
      matchedVulns,
      relatedVulns,
      rule,
      vendorGift,
      ...gift
    } = r;
    return gift;
  }

  function rematchScan(scan, options) {
    const opts = g.EdusrcMatcher.normalizeMatchOptions(options || scan.matchOptions);
    const gifts = scan.giftSnapshots || (scan.results || []).map(stripGiftSnapshot);
    const tangibleGifts =
      scan.tangibleSnapshots || (scan.tangibleResults || []).map(stripTangibleSnapshot);
    const vulns = scan.vulns || [];
    const results = g.EdusrcMatcher.matchCertificates(vulns, gifts, opts);
    const hints = g.EdusrcMatcher.buildScanHints(vulns, gifts, opts);
    const tangibleResults = g.EdusrcMatcher.matchTangibleGifts(
      scan.coins ?? null,
      tangibleGifts,
      vulns,
      opts,
      results
    );
    return {
      ...scan,
      results,
      hints,
      tangibleResults,
      matchOptions: opts,
      countableCount: vulns.filter((v) => g.EdusrcMatcher.isCountableVuln(v, opts)).length,
      approvedCount: vulns.filter((v) => v.approved).length,
    };
  }

  function rematchUserScan(scan, options) {
    const opts = g.EdusrcMatcher.normalizeMatchOptions({
      ...(scan.matchOptions || {}),
      ...(options || {}),
      publicProfile: true,
    });
    const gifts = scan.giftSnapshots || (scan.results || []).map(stripGiftSnapshot);
    const tangibleGifts =
      scan.tangibleSnapshots || (scan.tangibleResults || []).map(stripTangibleSnapshot);
    const vulns = scan.vulns || [];
    const results = g.EdusrcMatcher.matchCertificates(vulns, gifts, opts);
    const hints = g.EdusrcMatcher.buildScanHints(vulns, gifts, opts);
    const tangibleResults = g.EdusrcMatcher.matchTangibleGifts(
      scan.coins ?? null,
      tangibleGifts,
      vulns,
      opts,
      results
    );
    return {
      ...scan,
      results,
      hints,
      tangibleResults,
      matchOptions: opts,
      countableCount: vulns.filter((v) => g.EdusrcMatcher.isCountableVuln(v, opts)).length,
      approvedCount: vulns.filter((v) => v.approved).length,
    };
  }

  async function runUserScan(targetUserId, onProgress, options) {
    const opts = g.EdusrcMatcher.normalizeMatchOptions({ ...(options || {}), publicProfile: true });
    const progress = createScanProgress(onProgress);
    progress.vuln("开始分析他人…", 0);
    progress.gift("加载证书规则…", 0);
    progress.tangible("加载实物规则…", 0);

    const [{ vulns, userId, coins, meta, coinsEstimated }, { gifts, giftPages }, { gifts: tangibleGifts, tangiblePages }] =
      await Promise.all([
        fetchUserVulns(targetUserId, progress),
        getEnrichedGifts(progress),
        getEnrichedTangibleGifts(progress),
      ]);

    progress.matching("匹配可兑换礼品…");
    const results = g.EdusrcMatcher.matchCertificates(vulns, gifts, opts);
    const hints = [
      ...g.EdusrcMatcher.buildScanHints(vulns, gifts, opts),
      "公开主页不含审核状态，Rank>0 视为已通过",
      coinsEstimated ? "金币按 Rank 估算（1:1），实际余额可能不同" : "",
    ].filter(Boolean);
    const tangibleResults = g.EdusrcMatcher.matchTangibleGifts(
      coins,
      tangibleGifts,
      vulns,
      opts,
      results
    );
    progress.done("分析完成");

    return {
      scanMode: "user",
      userId,
      targetUser: {
        userId: String(targetUserId),
        nickname: meta.nickname || `用户 ${targetUserId}`,
        rank: meta.rank,
        approvedCount: meta.approvedCount,
        totalCount: meta.totalCount,
        profileUrl: `https://src.sjtu.edu.cn/profile/${targetUserId}/`,
      },
      coins,
      coinsEstimated,
      vulnCount: vulns.length,
      approvedCount: vulns.filter((v) => v.approved).length,
      countableCount: vulns.filter((v) => g.EdusrcMatcher.isCountableVuln(v, opts)).length,
      giftCount: gifts.length,
      giftPages,
      tangibleCount: tangibleGifts.length,
      tangiblePages,
      vulns,
      giftSnapshots: gifts,
      tangibleSnapshots: tangibleGifts,
      matchOptions: opts,
      results,
      hints: [...new Set(hints)].slice(0, 8),
      tangibleResults,
      scannedAt: Date.now(),
      engineVersion: g.__EDUSRC_ENGINE_V__,
    };
  }

  async function runScan(onProgress, options) {
    const opts = g.EdusrcMatcher.normalizeMatchOptions(options);
    const progress = createScanProgress(onProgress);
    progress.vuln("开始扫描…", 0);
    progress.gift("准备加载证书…", 0);
    progress.tangible("准备加载实物…", 0);
    const [{ vulns, userId, coins }, { gifts, giftPages }, { gifts: tangibleGifts, tangiblePages }] =
      await Promise.all([
        fetchAllVulns(progress),
        getEnrichedGifts(progress),
        getEnrichedTangibleGifts(progress),
      ]);
    progress.matching("匹配可兑换礼品…");
    const results = g.EdusrcMatcher.matchCertificates(vulns, gifts, opts);
    const hints = g.EdusrcMatcher.buildScanHints(vulns, gifts, opts);
    const tangibleResults = g.EdusrcMatcher.matchTangibleGifts(
      coins,
      tangibleGifts,
      vulns,
      opts,
      results
    );
    progress.done("扫描完成");
    return {
      scanMode: "self",
      userId,
      coins,
      vulnCount: vulns.length,
      approvedCount: vulns.filter((v) => v.approved).length,
      countableCount: vulns.filter((v) => g.EdusrcMatcher.isCountableVuln(v, opts)).length,
      giftCount: gifts.length,
      giftPages,
      tangibleCount: tangibleGifts.length,
      tangiblePages,
      vulns,
      giftSnapshots: gifts,
      tangibleSnapshots: tangibleGifts,
      matchOptions: opts,
      results,
      hints,
      tangibleResults,
      scannedAt: Date.now(),
      engineVersion: g.__EDUSRC_ENGINE_V__,
    };
  }

  g.EdusrcApi = { runScan, runUserScan, rematchScan, rematchUserScan, fetchPage, isLoginPage };
})(globalThis);
