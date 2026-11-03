(() => {
  "use strict";

  function bootstrapToken() {
    const fragment = new URLSearchParams(location.hash.slice(1));
    const fromFragment = fragment.get("token");
    if (fromFragment) {
      try {
        sessionStorage.setItem("php2shell-token", fromFragment);
      } catch (_) {}
      try {
        history.replaceState(null, "", location.pathname + location.search);
      } catch (_) {}
      return fromFragment;
    }
    try {
      return sessionStorage.getItem("php2shell-token") || "";
    } catch (_) {
      return "";
    }
  }

  const TOKEN = bootstrapToken();
  const VERSION = document.querySelector('meta[name="scanner-version"]').content;
  const $ = (id) => document.getElementById(id);
  const targetsEl = $("targets");
  const resultsBody = $("resultsBody");
  const emptyState = $("emptyState");
  const scanBtn = $("scanBtn");
  const cancelBtn = $("cancelBtn");
  const progressBar = $("progressBar");
  const progressText = $("progressText");
  const statusText = $("statusText");
  const searchEl = $("search");
  const filterEl = $("filter");
  const sortEl = $("sort");
  const toastEl = $("toast");

  if (!TOKEN) {
    const warning = $("authWarning");
    if (warning) warning.classList.remove("hidden");
    scanBtn.disabled = true;
    $("shutdownBtn").disabled = true;
  }

  const state = {
    results: [],
    scanning: false,
    verifying: false,
    selected: new Set(),
    total: 0,
    scanned: 0,
    startedAt: 0,
    timer: null,
    controller: null,
    filter: "all",
    query: "",
    sort: "arrival",
    toastTimer: null,
  };

  const OPTION_IDS = [
    "timeout", "concurrency", "delay", "maxRetries", "followRedirects", "deepCheck",
    "insecureTls", "allowPrivateTargets", "userAgent", "proxyUrl", "caCertFile", "extraHeaders", "extraCookies"
  ];

  function escapeHTML(value) {
    return String(value ?? "").replace(/[&<>"']/g, (c) => ({
      "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;"
    }[c]));
  }

  function resultKey(result) {
    return String(result && result.input ? result.input : "").trim().toLowerCase();
  }

  function selectedResults() {
    return state.results.filter((result) => state.selected.has(resultKey(result)));
  }

  function toast(message, isError = false) {
    clearTimeout(state.toastTimer);
    toastEl.textContent = message;
    toastEl.classList.toggle("err", isError);
    toastEl.classList.add("show");
    state.toastTimer = setTimeout(() => toastEl.classList.remove("show"), 4200);
  }

  function clampInt(value, min, max, fallback) {
    const n = Number.parseInt(value, 10);
    if (!Number.isFinite(n)) return fallback;
    return Math.min(max, Math.max(min, n));
  }

  function parseTargets(text) {
    const seen = new Set();
    const out = [];
    for (const rawLine of text.split(/\r?\n/)) {
      let line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      line = line.split(/\s+/)[0];
      if (line.includes(",") && !line.includes("?")) line = line.split(",")[0].trim();
      line = line.replace(/^["'<]+|["'>]+$/g, "");
      if (!line) continue;
      const key = line.toLowerCase().replace(/\/+$/, "");
      if (seen.has(key)) continue;
      seen.add(key);
      out.push(line);
    }
    return out;
  }

  function parseHeaderLines(text) {
    const out = {};
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const separator = line.indexOf(":");
      if (separator <= 0) continue;
      const name = line.slice(0, separator).trim();
      const value = line.slice(separator + 1).trim();
      if (name && value) out[name] = value;
    }
    return out;
  }

  function parseCookieLines(text) {
    const out = {};
    for (const rawLine of text.split(/\r?\n/)) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const separator = line.indexOf("=");
      if (separator <= 0) continue;
      const name = line.slice(0, separator).trim();
      const value = line.slice(separator + 1).trim();
      if (name) out[name] = value;
    }
    return out;
  }

  function updateTargetCount() {
    const count = parseTargets(targetsEl.value).length;
    $("targetCount").textContent = `${count} unik${count === 1 ? "" : "a"}`;
  }

  function readOptions() {
    return {
      timeoutSeconds: clampInt($("timeout").value, 2, 120, 10),
      concurrency: clampInt($("concurrency").value, 1, 32, 5),
      delayMs: clampInt($("delay").value, 0, 10000, 250),
      maxRetries: clampInt($("maxRetries").value, 0, 5, 2),
      followRedirects: $("followRedirects").checked,
      deepCheck: $("deepCheck").checked,
      insecureTls: $("insecureTls").checked,
      allowPrivateTargets: $("allowPrivateTargets").checked,
      userAgent: $("userAgent").value.trim() || `PHP2ShellChecker/${VERSION} (defensive vulnerability check)`,
      proxyUrl: $("proxyUrl").value.trim(),
      caCertFile: $("caCertFile").value.trim(),
      headers: parseHeaderLines($("extraHeaders").value),
      cookies: parseCookieLines($("extraCookies").value),
    };
  }

  function saveOptions() {
    try {
      const opts = readOptions();
      // Never persist credentials, cookies or proxy URLs in localStorage.
      // They may contain bearer tokens or session secrets.
      const persistent = {
        timeoutSeconds: opts.timeoutSeconds,
        concurrency: opts.concurrency,
        delayMs: opts.delayMs,
        maxRetries: opts.maxRetries,
        followRedirects: opts.followRedirects,
        deepCheck: opts.deepCheck,
        insecureTls: opts.insecureTls,
        allowPrivateTargets: opts.allowPrivateTargets,
        userAgent: opts.userAgent,
        caCertFile: opts.caCertFile,
      };
      localStorage.setItem("php2shell-options", JSON.stringify(persistent));
    } catch (_) {}
  }

  function loadOptions() {
    try {
      const saved = JSON.parse(localStorage.getItem("php2shell-options") || "null");
      if (!saved) return;
      if (saved.timeoutSeconds != null) $("timeout").value = saved.timeoutSeconds;
      if (saved.concurrency != null) $("concurrency").value = saved.concurrency;
      if (saved.delayMs != null) $("delay").value = saved.delayMs;
      if (saved.maxRetries != null) $("maxRetries").value = saved.maxRetries;
      if (typeof saved.followRedirects === "boolean") $("followRedirects").checked = saved.followRedirects;
      if (typeof saved.deepCheck === "boolean") $("deepCheck").checked = saved.deepCheck;
      if (typeof saved.insecureTls === "boolean") $("insecureTls").checked = saved.insecureTls;
      if (typeof saved.allowPrivateTargets === "boolean") $("allowPrivateTargets").checked = saved.allowPrivateTargets;
      if (saved.userAgent) $("userAgent").value = saved.userAgent;
      if (typeof saved.caCertFile === "string") $("caCertFile").value = saved.caCertFile;
      // Rewrite old entries so credentials saved by older versions are removed.
      saveOptions();
    } catch (_) {}
  }

  function setProgress(scanned, total) {
    state.scanned = scanned;
    state.total = total;
    const pct = total > 0 ? Math.min(100, (scanned / total) * 100) : 0;
    progressBar.style.width = pct + "%";
    progressText.textContent = `${scanned} / ${total}`;
  }

  function verdictClass(verdict) {
    return ({ vulnerable: "bad", php_unknown: "warn", safe: "good", not_php: "neutral", error: "err" })[verdict] || "neutral";
  }

  function badgeHTML(result) {
    return `<span class="badge ${verdictClass(result.verdict)}">${escapeHTML(result.verdictLabel || result.verdict)}</span>`;
  }

  function matches(result) {
    if (state.filter !== "all" && result.verdict !== state.filter) return false;
    if (!state.query) return true;
    const haystack = [
      result.input, result.finalUrl, result.phpVersion, result.server, result.poweredBy,
      result.app, result.verdictLabel, result.error,
      ...(result.evidence || []),
      ...(result.versionCandidates || []).flatMap((candidate) => [candidate.version, candidate.source]),
      ...(result.deepChecks || []).flatMap((check) => [check.url, check.phpVersion, check.versionSource, check.error]),
      ...(result.advisories || []).flatMap((a) => [a.cve, a.title, a.label, a.detail, a.recommendation, ...(a.evidence || [])]),
    ].join(" ").toLowerCase();
    return haystack.includes(state.query);
  }

  function sortResults(results) {
    const list = results.slice();
    if (state.sort === "url") {
      list.sort((a, b) => String(a.input).localeCompare(String(b.input), "sv"));
    } else if (state.sort === "severity") {
      const order = { vulnerable: 0, php_unknown: 1, error: 2, safe: 3, not_php: 4 };
      list.sort((a, b) => (order[a.verdict] ?? 9) - (order[b.verdict] ?? 9));
    }
    return list;
  }

  function sortedResults() {
    return sortResults(state.results.filter(matches));
  }

  // Export must include every scanned result, not only the rows that
  // currently match the search field or verdict filter.
  function allSortedResults() {
    return sortResults(state.results);
  }

  function detailHTML(result) {
    const fields = [
      ["Slutlig URL", result.finalUrl],
      ["HTTP-status", result.statusCode],
      ["Server", result.server],
      ["X-Powered-By", result.poweredBy],
      ["PHP-version", result.phpVersion ? result.phpVersion + (result.versionSource ? ` (${result.versionSource})` : "") : ""],
      ["Applikation", result.app],
      ["Svarstid", result.elapsedMs != null ? result.elapsedMs + " ms" : ""],
      ["Rättad version", result.fixedIn],
      ["TLS-verifiering", result.insecureTlsUsed ? "Avstängd" : ""],
      ["Serverns IP", result.remoteIp],
      ["Svarsskropp SHA-256", result.bodySha256],
      ["Fel", result.error],
      ["Kontrollerad", result.checkedAt],
    ].filter(([, value]) => value !== undefined && value !== null && value !== "");

    const evidence = (result.evidence || []).length
      ? `<div class="evidence"><h4>Bevis</h4><ul>${result.evidence.map((item) => `<li>${escapeHTML(item)}</li>`).join("")}</ul></div>`
      : "";

    const headers = result.responseHeaders && Object.keys(result.responseHeaders).length
      ? `<div class="evidence"><h4>HTTP-huvuden</h4><ul>${Object.entries(result.responseHeaders).map(([name, value]) => `<li><code>${escapeHTML(name)}</code>: ${escapeHTML(value)}</li>`).join("")}</ul></div>`
      : "";

    const versionSources = (result.versionCandidates || []).length
      ? `<div class="evidence"><h4>PHP-versionkällor</h4><ul>${result.versionCandidates.map((candidate) => `<li><code>${escapeHTML(candidate.version)}</code> via ${escapeHTML(candidate.source)} (styrka ${escapeHTML(candidate.confidence)})</li>`).join("")}</ul></div>`
      : "";

    const deepChecks = (result.deepChecks || []).length
      ? `<div class="evidence"><h4>Djupkontroller</h4><ul>${result.deepChecks.map((check) => {
          const status = check.error ? `fel: ${escapeHTML(check.error)}` : `HTTP ${escapeHTML(check.statusCode || "–")}`;
          const version = check.phpVersion ? ` · PHP ${escapeHTML(check.phpVersion)}` : "";
          return `<li><code>${escapeHTML(check.url)}</code> · ${status}${version}</li>`;
        }).join("")}</ul></div>`
      : "";

    const advisories = (result.advisories || []).map((a) => `
      <div class="advisory ${a.status === "possible" ? "possible" : ""}">
        <h4>${escapeHTML(a.cve)} · ${escapeHTML(a.title)} – ${escapeHTML(a.label)}</h4>
        ${a.detail ? `<p>${escapeHTML(a.detail)}</p>` : ""}
        ${a.recommendation ? `<p class="rec"><strong>Rekommendation:</strong> ${escapeHTML(a.recommendation)}</p>` : ""}
        ${(a.evidence || []).length ? `<ul>${a.evidence.map((item) => `<li>${escapeHTML(item)}</li>`).join("")}</ul>` : ""}
      </div>`).join("");

    return `
      <div class="detail-grid">
        ${fields.map(([label, value]) => `<div><span>${escapeHTML(label)}</span><strong>${escapeHTML(value)}</strong></div>`).join("")}
      </div>
      ${result.detail ? `<div class="detail-note">${escapeHTML(result.detail)}</div>` : ""}
      ${advisories}
      ${versionSources}
      ${deepChecks}
      ${evidence}
      ${headers}
    `;
  }

  function makeRow(result) {
    const key = resultKey(result);
    const tr = document.createElement("tr");
    tr.className = `result-row verdict-${result.verdict}`;
    tr.dataset.key = key;
    tr.innerHTML = `
      <td class="sel-cell"><input type="checkbox" class="row-select" aria-label="Markera ${escapeHTML(result.input)}"></td>
      <td class="url-cell">
        <div class="url">${escapeHTML(result.input)}</div>
        ${result.finalUrl && result.finalUrl !== result.input ? `<div class="final">${escapeHTML(result.finalUrl)}</div>` : ""}
        ${result.app ? `<span class="tag">${escapeHTML(result.app)}</span>` : ""}
        ${(result.advisories || []).some((a) => a.status === "possible") ? `<span class="tag warn">CVE-2026-115560</span>` : ""}
      </td>
      <td>${result.statusCode || "–"}</td>
      <td><span class="dot ${result.phpDetected ? "yes" : "no"}"></span>${result.phpDetected ? "Ja" : "Nej"}</td>
      <td>${result.phpVersion ? `<code>${escapeHTML(result.phpVersion)}</code>` : "–"}</td>
      <td>${badgeHTML(result)}</td>
      <td>${result.elapsedMs != null ? result.elapsedMs + " ms" : "–"}</td>
      <td class="chev">›</td>
    `;

    const detail = document.createElement("tr");
    detail.className = "detail-row hidden";
    detail.innerHTML = `<td colspan="8">${detailHTML(result)}</td>`;

    const checkbox = tr.querySelector(".row-select");
    checkbox.checked = state.selected.has(key);
    checkbox.addEventListener("change", () => {
      if (checkbox.checked) state.selected.add(key);
      else state.selected.delete(key);
      updateSelectionUI();
    });

    tr.addEventListener("click", (event) => {
      if (event.target.closest("input, button, a")) return;
      detail.classList.toggle("hidden");
      tr.querySelector(".chev").textContent = detail.classList.contains("hidden") ? "›" : "⌄";
    });
    return [tr, detail];
  }

  function renderAll() {
    resultsBody.replaceChildren();
    const list = sortedResults();
    for (const result of list) {
      const [row, detail] = makeRow(result);
      resultsBody.append(row, detail);
    }
    emptyState.classList.toggle("hidden", list.length > 0);
    if (list.length === 0) {
      if (state.results.length === 0) {
        emptyState.textContent = "Inga resultat ännu. Lägg till en eller flera webbplatser och starta skanningen.";
      } else {
        emptyState.textContent = "Inga resultat matchar filtret eller sökningen.";
      }
    }
    updateStats();
    updateSelectionUI();
  }

  function updateStats() {
    const counts = { all: state.results.length, vulnerable: 0, php_unknown: 0, safe: 0, not_php: 0, error: 0 };
    for (const result of state.results) {
      if (counts[result.verdict] != null) counts[result.verdict]++;
    }
    $("statTotal").textContent = counts.all;
    $("statVulnerable").textContent = counts.vulnerable;
    $("statUnknown").textContent = counts.php_unknown;
    $("statSafe").textContent = counts.safe;
    $("statNotPhp").textContent = counts.not_php;
    $("statErrors").textContent = counts.error;
    const hasResults = state.results.length > 0;
    $("exportCsv").disabled = !hasResults;
    $("exportJson").disabled = !hasResults;
  }

  function updateSelectionUI() {
    const selected = selectedResults().length;
    $("selectionBar").classList.toggle("hidden", selected === 0);
    $("selectionCount").textContent = `${selected} vald${selected === 1 ? "" : "a"} värd${selected === 1 ? "" : "ar"}`;

    const boxes = Array.from(resultsBody.querySelectorAll(".row-select"));
    const checked = boxes.filter((box) => box.checked).length;
    const selectAll = $("selectAll");
    selectAll.checked = boxes.length > 0 && checked === boxes.length;
    selectAll.indeterminate = checked > 0 && checked < boxes.length;

    $("verifySelected").disabled = state.verifying || selected === 0 || !TOKEN;
    $("reportHtml").disabled = selected === 0;
    $("reportJson").disabled = selected === 0;
    $("clearSelection").disabled = state.verifying || selected === 0;
  }

  function setVisibleSelection(checked) {
    resultsBody.querySelectorAll(".result-row").forEach((row) => {
      const box = row.querySelector(".row-select");
      if (!box) return;
      const key = row.dataset.key || "";
      if (!key) return;
      box.checked = checked;
      if (checked) state.selected.add(key);
      else state.selected.delete(key);
    });
    updateSelectionUI();
  }

  function addResult(result) {
    state.results.push(result);
    if (matches(result)) {
      const [row, detail] = makeRow(result);
      resultsBody.append(row, detail);
      emptyState.classList.add("hidden");
    }
    updateStats();
    updateSelectionUI();
  }

  function resetResults() {
    state.results = [];
    state.selected.clear();
    resultsBody.replaceChildren();
    emptyState.classList.remove("hidden");
    emptyState.textContent = "Skannar… resultat visas här allt eftersom.";
    setProgress(0, 0);
    updateStats();
    updateSelectionUI();
  }

  function setScanning(active) {
    state.scanning = active;
    scanBtn.classList.toggle("hidden", active);
    cancelBtn.classList.toggle("hidden", !active);
    saveOptions();
    if (active) {
      state.startedAt = performance.now();
      clearInterval(state.timer);
      state.timer = setInterval(() => {
        if (!state.scanning) return;
        const seconds = ((performance.now() - state.startedAt) / 1000).toFixed(1);
        statusText.textContent = `Skannar… ${seconds} s`;
      }, 200);
    } else {
      clearInterval(state.timer);
      state.timer = null;
    }
  }

  function handleEvent(event) {
    if (event.type === "start") {
      setProgress(0, event.total || 0);
      statusText.textContent = `Skannar ${event.total} webbplats${event.total === 1 ? "" : "er"}…`;
      return;
    }
    if (event.type === "result" && event.result) {
      addResult(event.result);
      setProgress(state.scanned + 1, state.total);
      return;
    }
    if (event.type === "done") {
      setProgress(event.scanned != null ? event.scanned : state.results.length, Math.max(state.total, state.results.length));
      const seconds = event.elapsedMs != null ? (event.elapsedMs / 1000).toFixed(1) : null;
      statusText.textContent = `Klart${seconds ? ` på ${seconds} s` : ""} – ${state.results.length} resultat`;
      return;
    }
    if (event.type === "error") {
      toast(event.message || "Skannern rapporterade ett fel.", true);
    }
  }

  async function startScan() {
    if (!TOKEN) {
      toast("Token saknas. Öppna adressen som skrevs ut i terminalen.", true);
      return;
    }
    if (state.scanning) {
      cancelScan();
      return;
    }
    const targets = parseTargets(targetsEl.value);
    if (targets.length === 0) {
      toast("Lägg till minst en webbplats först.", true);
      targetsEl.focus();
      return;
    }

    resetResults();
    setScanning(true);
    statusText.textContent = "Ansluter…";
    const controller = new AbortController();
    state.controller = controller;

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Scanner-Token": TOKEN,
        },
        body: JSON.stringify({ targets, options: readOptions() }),
        signal: controller.signal,
      });

      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || `HTTP ${response.status}`);
      }
      if (!response.body) throw new Error("Webbläsaren stöder inte strömmande svar.");

      const reader = response.body.getReader();
      const decoder = new TextDecoder();
      let buffer = "";
      while (true) {
        const { value, done } = await reader.read();
        if (done) break;
        buffer += decoder.decode(value, { stream: true });
        let newline;
        while ((newline = buffer.indexOf("\n")) >= 0) {
          const line = buffer.slice(0, newline).trim();
          buffer = buffer.slice(newline + 1);
          if (!line) continue;
          try {
            handleEvent(JSON.parse(line));
          } catch (_) {
            // Ignore a partial or malformed line; the next line can still be valid.
          }
        }
      }
      if (buffer.trim()) {
        try { handleEvent(JSON.parse(buffer.trim())); } catch (_) {}
      }
    } catch (error) {
      if (error.name === "AbortError") {
        statusText.textContent = `Avbruten – ${state.results.length} resultat`;
        toast("Skanningen avbröts.");
      } else {
        statusText.textContent = "Fel: " + error.message;
        toast("Fel: " + error.message, true);
      }
    } finally {
      state.controller = null;
      setScanning(false);
      if (statusText.textContent.startsWith("Skannar") || statusText.textContent === "Ansluter…") {
        statusText.textContent = `Klart – ${state.results.length} resultat`;
      }
    }
  }

  function cancelScan() {
    if (state.controller) state.controller.abort();
  }

  async function readEventStream(response, onEvent) {
    if (!response.body) throw new Error("Webbläsaren stöder inte strömmande svar.");
    const reader = response.body.getReader();
    const decoder = new TextDecoder();
    let buffer = "";
    while (true) {
      const { value, done } = await reader.read();
      if (done) break;
      buffer += decoder.decode(value, { stream: true });
      let newline;
      while ((newline = buffer.indexOf("\n")) >= 0) {
        const line = buffer.slice(0, newline).trim();
        buffer = buffer.slice(newline + 1);
        if (!line) continue;
        try { onEvent(JSON.parse(line)); } catch (_) {}
      }
    }
    if (buffer.trim()) {
      try { onEvent(JSON.parse(buffer.trim())); } catch (_) {}
    }
  }

  // Re-runs the ordinary, non-invasive scan for the selected hosts and
  // replaces those rows with fresh evidence. Nothing is written to the target.
  async function verifySelected() {
    if (!TOKEN) {
      toast("Token saknas. Öppna adressen som skrevs ut i terminalen.", true);
      return;
    }
    if (state.verifying || state.scanning) return;
    const chosen = selectedResults();
    if (chosen.length === 0) {
      toast("Markera minst en värd först.", true);
      return;
    }
    const preview = chosen.slice(0, 8).map((r) => r.input).join("\n");
    const more = chosen.length > 8 ? `\n… och ${chosen.length - 8} till` : "";
    if (!confirm(`Verifiera ${chosen.length} vald${chosen.length === 1 ? "" : "a"} värd${chosen.length === 1 ? "" : "ar"} med nya GET-förfrågningar?\n\n${preview}${more}\n\nKontrollen är icke-invasiv och ändrar inget på servern.`)) return;

    state.verifying = true;
    updateSelectionUI();
    const previousStatus = statusText.textContent;
    statusText.textContent = `Verifierar ${chosen.length} värd${chosen.length === 1 ? "" : "ar"}…`;

    try {
      const response = await fetch("/api/scan", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "X-Scanner-Token": TOKEN,
        },
        body: JSON.stringify({ targets: chosen.map((r) => r.input), options: readOptions() }),
      });
      if (!response.ok) {
        const text = await response.text();
        throw new Error(text || `HTTP ${response.status}`);
      }

      let updated = 0;
      await readEventStream(response, (event) => {
        if (event.type !== "result" || !event.result) return;
        const fresh = event.result;
        const key = resultKey(fresh);
        const index = state.results.findIndex((item) => resultKey(item) === key);
        if (index >= 0) state.results[index] = fresh;
        else state.results.push(fresh);
        updated++;
      });

      renderAll();
      statusText.textContent = `Verifiering klar – ${updated} värd${updated === 1 ? "" : "ar"} uppdaterade`;
      toast(`Verifierade ${updated} värd${updated === 1 ? "" : "ar"}. Bevisen är uppdaterade.`);
    } catch (error) {
      statusText.textContent = previousStatus;
      toast("Verifiering misslyckades: " + error.message, true);
    } finally {
      state.verifying = false;
      updateSelectionUI();
    }
  }

  const VERDICT_ORDER = { vulnerable: 0, php_unknown: 1, error: 2, safe: 3, not_php: 4 };

  function reportResults() {
    return selectedResults().slice().sort((a, b) => {
      const byVerdict = (VERDICT_ORDER[a.verdict] ?? 9) - (VERDICT_ORDER[b.verdict] ?? 9);
      if (byVerdict !== 0) return byVerdict;
      return String(a.input).localeCompare(String(b.input), "sv");
    });
  }

  function summarizeResults(results) {
    return results.reduce((acc, result) => {
      acc[result.verdict] = (acc[result.verdict] || 0) + 1;
      return acc;
    }, {});
  }

  function reportMeta() {
    return {
      report: "PHP2Shell Checker – bevisrapport",
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      tool: "PHP2Shell Checker",
      version: VERSION,
      cves: ["CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"],
      methodology: "Icke-invasiv kontroll med ordinarie HTTP GET-förfrågningar. Djupanalysen kombinerar PHP-indikatorer från cookies med versioner från svarshuvuden, HTML, phpinfo-liknande sidor och ett fåtal vanliga diagnostiksökvägar. Inga exploit-payloads skickades, inga filer laddades upp och ingen åtkomst etablerades. Ingen ändring gjordes på målservern.",
      limitation: "Resultatet är en indikation på PHP-version och konfiguration, inte ett bevis på att sårbarheten är utnyttjad eller utnyttjadbar.",
    };
  }

  function buildEvidenceHTML(results) {
    const meta = reportMeta();
    const generatedText = new Date().toLocaleString("sv-SE", { dateStyle: "long", timeStyle: "medium" });
    const counts = summarizeResults(results);
    const summaryRow = (label, value) => `<div class="sum"><span>${escapeHTML(value)}</span><small>${escapeHTML(label)}</small></div>`;

    const hostSections = results.map((r, index) => {
      const fields = [
        ["Slutlig URL", r.finalUrl],
        ["HTTP-status", r.statusCode],
        ["Serverns IP", r.remoteIp],
        ["PHP-version", r.phpVersion ? r.phpVersion + (r.versionSource ? ` (källa: ${r.versionSource})` : "") : ""],
        ["Rättad version", r.fixedIn],
        ["TLS-verifiering", r.insecureTlsUsed ? "Avstängd" : ""],
        ["Server", r.server],
        ["X-Powered-By", r.poweredBy],
        ["Applikation", r.app],
        ["Svarstid", r.elapsedMs != null ? r.elapsedMs + " ms" : ""],
        ["Kontrollerad", r.checkedAt],
        ["Svarsskropp SHA-256", r.bodySha256],
        ["Fel", r.error],
      ].filter(([, value]) => value !== undefined && value !== null && value !== "");

      const advisories = (r.advisories || []).map((a) => `
        <div class="advisory">
          <strong>${escapeHTML(a.cve)} · ${escapeHTML(a.title)} – ${escapeHTML(a.label)}</strong>
          ${a.detail ? `<p>${escapeHTML(a.detail)}</p>` : ""}
          ${a.recommendation ? `<p><em>Rekommendation:</em> ${escapeHTML(a.recommendation)}</p>` : ""}
          ${(a.evidence || []).length ? `<ul>${a.evidence.map((item) => `<li>${escapeHTML(item)}</li>`).join("")}</ul>` : ""}
        </div>`).join("");

      const headers = r.responseHeaders && Object.keys(r.responseHeaders).length
        ? `<h4>HTTP-huvuden</h4><table class="headers"><tbody>${Object.entries(r.responseHeaders).map(([name, value]) => `<tr><th>${escapeHTML(name)}</th><td>${escapeHTML(value)}</td></tr>`).join("")}</tbody></table>`
        : "";

      const versionSources = (r.versionCandidates || []).length
        ? `<h4>PHP-versionkällor</h4><ul>${r.versionCandidates.map((candidate) => `<li><code>${escapeHTML(candidate.version)}</code> via ${escapeHTML(candidate.source)} (styrka ${escapeHTML(candidate.confidence)})</li>`).join("")}</ul>`
        : "";

      const deepChecks = (r.deepChecks || []).length
        ? `<h4>Djupkontroller</h4><table class="headers"><tbody>${r.deepChecks.map((check) => {
            const detail = check.error ? `fel: ${check.error}` : `HTTP ${check.statusCode || "–"}${check.phpVersion ? ` · PHP ${check.phpVersion}` : ""}`;
            return `<tr><th>${escapeHTML(check.url)}</th><td>${escapeHTML(detail)}</td></tr>`;
          }).join("")}</tbody></table>`
        : "";

      return `
        <section class="host">
          <h3><span class="num">${index + 1}.</span> ${escapeHTML(r.input)}</h3>
          <span class="verdict ${verdictClass(r.verdict)}">${escapeHTML(r.verdictLabel || r.verdict)}</span>
          ${r.detail ? `<p>${escapeHTML(r.detail)}</p>` : ""}
          <dl>${fields.map(([label, value]) => `<div><dt>${escapeHTML(label)}</dt><dd>${escapeHTML(value)}</dd></div>`).join("")}</dl>
          ${advisories}
          ${versionSources}
          ${deepChecks}
          ${(r.evidence || []).length ? `<h4>Bevis</h4><ul>${r.evidence.map((item) => `<li>${escapeHTML(item)}</li>`).join("")}</ul>` : ""}
          ${headers}
        </section>`;
    }).join("");

    return `<!doctype html>
<html lang="sv">
<head>
<meta charset="utf-8">
<title>PHP2Shell – bevisrapport ${escapeHTML(timestamp())}</title>
<style>
  :root { color-scheme: light; }
  * { box-sizing: border-box; }
  body { margin: 0; padding: 28px; background: #f4f7fb; color: #16202e; font: 13px/1.5 "Segoe UI", system-ui, sans-serif; }
  .sheet { max-width: 980px; margin: 0 auto; background: #fff; border: 1px solid #d7e0ec; border-radius: 10px; padding: 34px 38px; }
  h1 { margin: 0 0 4px; font-size: 24px; letter-spacing: -.02em; }
  .sub { margin: 0 0 18px; color: #5c6f88; }
  .meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(220px, 1fr)); gap: 4px 20px; font-size: 12px; color: #33465f; margin-bottom: 22px; }
  .meta b { color: #16202e; }
  h2 { font-size: 15px; margin: 26px 0 8px; padding-bottom: 5px; border-bottom: 1px solid #e2e9f3; }
  h3 { font-size: 14px; margin: 0 0 4px; }
  h4 { font-size: 11px; text-transform: uppercase; letter-spacing: .06em; color: #5c6f88; margin: 14px 0 4px; }
  p { margin: 0 0 8px; }
  ul { margin: 4px 0 8px; padding-left: 18px; }
  li { margin: 2px 0; }
  .sum-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(120px, 1fr)); gap: 8px; }
  .sum { border: 1px solid #e2e9f3; border-radius: 8px; padding: 8px 10px; background: #fafcff; }
  .sum span { display: block; font-size: 20px; font-weight: 700; }
  .sum small { color: #5c6f88; font-size: 10.5px; text-transform: uppercase; letter-spacing: .05em; }
  .host { border: 1px solid #e2e9f3; border-radius: 9px; padding: 14px 16px; margin: 0 0 14px; break-inside: avoid; page-break-inside: avoid; }
  .host .num { color: #5c6f88; }
  .verdict { display: inline-block; font-weight: 700; font-size: 11px; padding: 2px 8px; border-radius: 999px; margin: 2px 0 8px; border: 1px solid; }
  .verdict.bad { color: #8d1024; background: #ffe8eb; border-color: #f5b6c0; }
  .verdict.warn { color: #7a4a00; background: #fff4dd; border-color: #f3d59a; }
  .verdict.good { color: #0b5d3d; background: #e4f8ee; border-color: #a9e3c8; }
  .verdict.neutral, .verdict.err { color: #38485c; background: #eef2f7; border-color: #d3dce8; }
  dl { display: grid; grid-template-columns: repeat(auto-fit, minmax(210px, 1fr)); gap: 6px 18px; margin: 10px 0; }
  dl div { min-width: 0; }
  dt { color: #5c6f88; font-size: 10px; text-transform: uppercase; letter-spacing: .05em; }
  dd { margin: 1px 0 0; word-break: break-all; font-size: 11.5px; }
  .advisory { border: 1px solid #f3d59a; background: #fffaf0; border-radius: 8px; padding: 8px 10px; margin: 10px 0; font-size: 12px; }
  .advisory p { margin: 4px 0; }
  table.headers { width: 100%; border-collapse: collapse; margin-top: 8px; font-size: 11px; }
  table.headers th, table.headers td { text-align: left; padding: 3px 6px; border-bottom: 1px solid #edf1f7; vertical-align: top; }
  table.headers th { width: 170px; color: #5c6f88; font-weight: 600; }
  .note { font-size: 11.5px; color: #43566f; background: #f7faff; border: 1px solid #e2e9f3; border-radius: 8px; padding: 10px 12px; }
  .sign { display: grid; grid-template-columns: 1fr 1fr; gap: 26px; margin-top: 26px; font-size: 11.5px; }
  .sign div { border-top: 1px solid #8fa2b9; padding-top: 5px; color: #5c6f88; }
  .foot { margin-top: 22px; padding-top: 10px; border-top: 1px solid #e2e9f3; font-size: 10.5px; color: #72839a; }
  @page { size: A4; margin: 16mm; }
  @media print {
    body { background: #fff; padding: 0; font-size: 11px; }
    .sheet { border: 0; border-radius: 0; padding: 0; max-width: none; }
    .no-print { display: none !important; }
    h2 { break-after: avoid; }
  }
</style>
</head>
<body>
<div class="sheet">
  <h1>PHP2Shell – bevisrapport</h1>
  <p class="sub">Underlag för IT-drift och säkerhetsledning</p>

  <div class="meta">
    <div><b>Framtagen:</b> ${escapeHTML(generatedText)}</div>
    <div><b>Verktyg:</b> ${escapeHTML(meta.tool)} v${escapeHTML(meta.version)}</div>
    <div><b>Antal värdar:</b> ${results.length}</div>
    <div><b>Rapport-ID:</b> ${escapeHTML(timestamp())}-${results.length}</div>
  </div>

  <h2>Sammanfattning</h2>
  <div class="sum-grid">
    ${summaryRow("Totalt", results.length)}
    ${summaryRow("Sårbara", counts.vulnerable || 0)}
    ${summaryRow("Okänd version", counts.php_unknown || 0)}
    ${summaryRow("Åtgärdade", counts.safe || 0)}
    ${summaryRow("Inte PHP", counts.not_php || 0)}
    ${summaryRow("Fel", counts.error || 0)}
  </div>

  <h2>Metod och avgränsning</h2>
  <p class="note">${escapeHTML(meta.methodology)}</p>
  <p class="note">${escapeHTML(meta.limitation)} Kontrollera alltid fynd mot serverns pakethanterare, kontrollpanel eller hostingleverantör.</p>

  <h2>Granskade värdar</h2>
  ${hostSections}

  <h2>Utlåtande och signatur</h2>
  <p>Rapporten sammanställer resultat från en icke-invasiv sårbarhetskontroll. Bedömningen avser PHP2Shell (CVE-2026-109618 och CVE-2026-109619) samt rekommendationen för CVE-2026-115560.</p>
  <div class="sign">
    <div>Utförd av (namn, funktion)</div>
    <div>Datum och underskrift</div>
    <div>Beställare / mottagare</div>
    <div>Diarienummer eller ärendereferens</div>
  </div>

  <p class="foot">Bedömningsskala: Sårbar = PHP-versionen är äldre än den rättade versionen i samma gren. Okänd version = PHP upptäcktes men versionen kunde inte fastställas. Åtgärdad = versionen är samma som eller nyare än den rättade. Rapporten får endast användas för system som organisationen äger eller har uttryckligt tillstånd att testa.</p>
</div>
</body>
</html>`;
  }

  function exportEvidenceHTML() {
    const results = reportResults();
    if (results.length === 0) return toast("Markera minst en värd först.", true);
    download(`php2shell-bevis-${timestamp()}.html`, buildEvidenceHTML(results), "text/html;charset=utf-8");
    toast(`Bevisrapport för ${results.length} värd${results.length === 1 ? "" : "ar"} exporterad som HTML.`);
  }

  function exportEvidenceJSON() {
    const results = reportResults();
    if (results.length === 0) return toast("Markera minst en värd först.", true);
    const payload = {
      ...reportMeta(),
      summary: summarizeResults(results),
      hosts: results,
    };
    download(`php2shell-bevis-${timestamp()}.json`, JSON.stringify(payload, null, 2), "application/json");
    toast(`Bevisrapport för ${results.length} värd${results.length === 1 ? "" : "ar"} exporterad som JSON.`);
  }

  function download(filename, content, type) {
    const blob = new Blob([content], { type });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1500);
  }

  function timestamp() {
    const d = new Date();
    const pad = (n) => String(n).padStart(2, "0");
    return `${d.getFullYear()}${pad(d.getMonth() + 1)}${pad(d.getDate())}-${pad(d.getHours())}${pad(d.getMinutes())}${pad(d.getSeconds())}`;
  }

  function csvEscape(value) {
    let text = value == null ? "" : String(value);
    // Neutralize spreadsheet formulas in attacker-controlled values such as
    // URLs, headers and page evidence. The leading apostrophe is harmless in
    // Excel/LibreOffice and keeps the exported value as text.
    if (/^[=+\-@\t\r]/.test(text)) text = "'" + text;
    return /[";\n\r]/.test(text) ? `"${text.replace(/"/g, '""')}"` : text;
  }

  function exportCSV() {
    if (state.results.length === 0) return toast("Inga resultat att exportera.", true);
    const headers = [
      "Webbplats", "Slutlig URL", "HTTP-status", "PHP", "PHP-version", "Versionkälla", "TLS-verifiering",
      "PHP-versionkällor", "Djupkontroller",
      "Bedömning", "Allvarlighet", "Rättad version", "Server", "X-Powered-By", "Applikation",
      "PHP-länkar", "Svarstid (ms)", "Detaljer", "CVE-2026-115560", "Rekommendation (CVE-2026-115560)",
      "Bevis", "Fel", "Kontrollerad", "Serverns IP", "Svarsskropp SHA-256", "HTTP-huvuden"
    ];
    const rows = allSortedResults().map((r) => [
      r.input, r.finalUrl, r.statusCode, r.phpDetected ? "Ja" : "Nej", r.phpVersion, r.versionSource,
      r.insecureTlsUsed ? "Avstängd" : "",
      (r.versionCandidates || []).map((candidate) => `${candidate.version} (${candidate.source}, styrka ${candidate.confidence})`).join(" | "),
      (r.deepChecks || []).map((check) => `${check.url} ${check.error ? `fel: ${check.error}` : `HTTP ${check.statusCode || "–"}${check.phpVersion ? ` PHP ${check.phpVersion}` : ""}`}`).join(" | "),
      r.verdictLabel, r.verdict, r.fixedIn, r.server, r.poweredBy, r.app,
      r.phpLinks, r.elapsedMs, r.detail,
      (r.advisories || []).map((a) => `${a.cve}: ${a.label}`).join(" | "),
      (r.advisories || []).map((a) => a.recommendation).filter(Boolean).join(" | "),
      (r.evidence || []).join(" | "), r.error, r.checkedAt,
      r.remoteIp, r.bodySha256,
      Object.entries(r.responseHeaders || {}).map(([name, value]) => `${name}: ${value}`).join(" | ")
    ]);
    const csv = "\uFEFF" + [headers, ...rows].map((row) => row.map(csvEscape).join(";")).join("\r\n") + "\r\n";
    download(`php2shell-resultat-${timestamp()}.csv`, csv, "text/csv;charset=utf-8");
    toast(`Exporterade ${rows.length} resultat till CSV.`);
  }

  function exportJSON() {
    if (state.results.length === 0) return toast("Inga resultat att exportera.", true);
    const payload = {
      schemaVersion: 1,
      generatedAt: new Date().toISOString(),
      scanner: "PHP2Shell Checker",
      version: VERSION,
      cves: ["CVE-2026-109618", "CVE-2026-109619", "CVE-2026-115560"],
      summary: state.results.reduce((acc, r) => {
        acc[r.verdict] = (acc[r.verdict] || 0) + 1;
        return acc;
      }, {}),
      results: allSortedResults(),
    };
    download(`php2shell-resultat-${timestamp()}.json`, JSON.stringify(payload, null, 2), "application/json");
    toast(`Exporterade ${state.results.length} resultat till JSON.`);
  }

  async function shutdownScanner() {
    if (!TOKEN) {
      toast("Token saknas. Öppna adressen som skrevs ut i terminalen.", true);
      return;
    }
    if (!confirm("Stänga av PHP2Shell Checker? En pågående skanning avbryts.")) return;
    if (state.controller) state.controller.abort();
    try {
      await fetch("/api/shutdown", {
        method: "POST",
        headers: { "X-Scanner-Token": TOKEN },
      });
    } catch (_) {}
    document.body.innerHTML = `
      <div class="shutdown-screen">
        <div>
          <div class="shutdown-icon">■</div>
          <h1 class="shutdown-title">PHP2Shell Checker är avstängd</h1>
          <p class="shutdown-text">Du kan stänga den här fliken.</p>
        </div>
      </div>`;
  }

  async function loadFile(file) {
    if (!file) return;
    if (file.size > 5 * 1024 * 1024) {
      toast("Filen är för stor (max 5 MB).", true);
      return;
    }
    let text;
    try {
      text = await file.text();
    } catch (error) {
      toast(`Kunde inte läsa ${file.name}: ${error.message}`, true);
      return;
    }
    const existing = targetsEl.value.trim();
    targetsEl.value = (existing ? existing + "\n" : "") + text;
    updateTargetCount();
    toast(`Laddade ${file.name}`);
  }

  function setFilter(value) {
    state.filter = value;
    filterEl.value = value;
    renderAll();
  }

  // Event wiring
  targetsEl.addEventListener("input", updateTargetCount);
  $("pickFile").addEventListener("click", () => $("fileInput").click());
  $("fileInput").addEventListener("change", async (event) => {
    await loadFile(event.target.files[0]);
    event.target.value = "";
  });
  $("clearTargets").addEventListener("click", () => {
    targetsEl.value = "";
    updateTargetCount();
    targetsEl.focus();
  });
  scanBtn.addEventListener("click", startScan);
  cancelBtn.addEventListener("click", cancelScan);

  const dropZone = $("dropZone");
  ["dragenter", "dragover"].forEach((name) => {
    dropZone.addEventListener(name, (event) => {
      event.preventDefault();
      dropZone.classList.add("drag");
    });
  });
  ["dragleave", "drop"].forEach((name) => {
    dropZone.addEventListener(name, (event) => {
      event.preventDefault();
      dropZone.classList.remove("drag");
    });
  });
  dropZone.addEventListener("drop", async (event) => {
    const file = event.dataTransfer.files && event.dataTransfer.files[0];
    if (file) await loadFile(file);
  });

  searchEl.addEventListener("input", () => {
    state.query = searchEl.value.trim().toLowerCase();
    renderAll();
  });
  filterEl.addEventListener("change", () => setFilter(filterEl.value));
  sortEl.addEventListener("change", () => {
    state.sort = sortEl.value;
    renderAll();
  });
  document.querySelectorAll(".stat").forEach((stat) => {
    const activate = () => setFilter(stat.dataset.filter || "all");
    stat.addEventListener("click", activate);
    stat.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        event.preventDefault();
        activate();
      }
    });
  });

  $("exportCsv").addEventListener("click", exportCSV);
  $("exportJson").addEventListener("click", exportJSON);
  $("shutdownBtn").addEventListener("click", shutdownScanner);

  $("selectAll").addEventListener("change", (event) => setVisibleSelection(event.target.checked));
  $("verifySelected").addEventListener("click", verifySelected);
  $("reportHtml").addEventListener("click", exportEvidenceHTML);
  $("reportJson").addEventListener("click", exportEvidenceJSON);
  $("clearSelection").addEventListener("click", () => {
    state.selected.clear();
    renderAll();
  });

  OPTION_IDS.forEach((id) => {
    const el = $(id);
    el.addEventListener("change", saveOptions);
    el.addEventListener("input", saveOptions);
  });

  loadOptions();
  updateTargetCount();
  updateStats();
  fetch("/api/health").then((response) => response.json()).then((data) => {
    if (data.version) $("versionPill").textContent = "v" + data.version;
    if (data.buildTime) {
      $("buildInfo").textContent = `Version ${data.version} · build #${data.buildNumber} · ${data.buildTime} · commit ${data.buildCommit}`;
    }
  }).catch(() => {});
})();
