/**
 * main.js
 * -------
 * Drives the PhishGuard AI dashboard: submits URLs to /api/analyze,
 * renders the verdict gauge, the "URL autopsy" character breakdown
 * (this page's signature visual), the SHAP explanation bars, domain
 * intelligence + VirusTotal panels, the research panel, recent-activity
 * stats, the scan history table, and the model/dataset dossier.
 *
 * No frameworks/libraries — vanilla JS only, per project scope.
 */

// Populated from GET /api/lexicon at load time -- single source of truth
// shared with backend/utils/feature_extractor.py so the "URL autopsy"
// highlighting can never drift out of sync with what the model actually sees.
let SUSPICIOUS_KEYWORDS = [];

const FEATURE_LABELS = {
  url_length: "URL length",
  num_dots: "Dots",
  num_hyphens: "Hyphens",
  has_ip: "Uses raw IP",
  has_https: "Uses HTTPS",
  suspicious_keyword_count: "Suspicious keywords",
  num_digits: "Digit count",
  num_subdomains: "Subdomains",
  has_at_symbol: "'@' symbol present",
  is_shortened: "Link shortener",
  shannon_entropy: "Entropy (bits/char)",
  digit_ratio: "Digit ratio",
  special_char_ratio: "Special-char ratio",
  longest_token_length: "Longest token",
  suspicious_tld: "Suspicious TLD",
  max_char_repeat: "Longest repeated run",
  path_depth: "Path depth",
  query_param_count: "Query params",
  encoded_char_count: "Encoded chars",
  suspicious_keyword_density: "Keyword density",
};

const form = document.getElementById("analyze-form");
const input = document.getElementById("url-input");
const analyzeBtn = document.getElementById("analyze-btn");
const formError = document.getElementById("form-error");
const resultsSection = document.getElementById("results");
const scanProgress = document.getElementById("scan-progress");

form.addEventListener("submit", (e) => {
  e.preventDefault();
  runAnalysis(input.value.trim());
});

document.querySelectorAll(".chip[data-url]").forEach((btn) => {
  btn.addEventListener("click", () => {
    input.value = btn.dataset.url;
    runAnalysis(btn.dataset.url);
  });
});

document.getElementById("clear-history-btn").addEventListener("click", async () => {
  await fetch("/api/history/clear", { method: "POST" });
  loadHistory();
  toast("Scan history cleared.", "success");
});

document.getElementById("research-toggle").addEventListener("click", () => {
  const btn = document.getElementById("research-toggle");
  const body = document.getElementById("research-body");
  const expanded = btn.getAttribute("aria-expanded") === "true";
  btn.setAttribute("aria-expanded", String(!expanded));
  body.hidden = expanded;
  if (!expanded && !body.dataset.loaded) loadResearchInfo();
});

async function runAnalysis(url) {
  formError.textContent = "";
  if (!url) {
    formError.textContent = "Enter a URL first.";
    return;
  }

  setLoading(true);
  try {
    const res = await fetch("/api/analyze", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ url }),
    });
    const data = await res.json();

    if (!res.ok) {
      const msg = data.error || "Something went wrong.";
      formError.textContent = msg;
      toast(msg, "error");
      return;
    }

    renderResult(data);
    loadHistory();
    loadSupplementaryPanels(data.url);
    toast(`Analysis complete — ${data.prediction === "phishing" ? "flagged as phishing" : "looks legitimate"}.`, data.prediction === "phishing" ? "error" : "success");
  } catch (err) {
    const msg = "Network error — is the backend running?";
    formError.textContent = msg;
    toast(msg, "error");
    console.error(err);
  } finally {
    setLoading(false);
  }
}

function setLoading(isLoading) {
  analyzeBtn.disabled = isLoading;
  analyzeBtn.querySelector(".btn-label").hidden = isLoading;
  analyzeBtn.querySelector(".btn-spinner").hidden = !isLoading;
  scanProgress.hidden = !isLoading;
}

/** Lightweight toast notification (Phase 10 polish). */
function toast(message, kind = "success") {
  const stack = document.getElementById("toast-stack");
  const el = document.createElement("div");
  el.className = `toast toast--${kind}`;
  el.textContent = message;
  stack.appendChild(el);
  setTimeout(() => {
    el.style.opacity = "0";
    el.style.transition = "opacity 0.3s ease";
    setTimeout(() => el.remove(), 300);
  }, 3800);
}

function renderResult(data) {
  resultsSection.hidden = false;

  // --- verdict badge + gauge -------------------------------------------
  const isPhishing = data.prediction === "phishing";
  document.getElementById("case-id").textContent = `Case #${String(data.id).padStart(4, "0")}`;
  document.getElementById("verdict-url").textContent = data.url;

  const badge = document.getElementById("verdict-badge");
  badge.className = "verdict-badge " + (isPhishing ? "verdict-badge--phishing" : "verdict-badge--legitimate");
  document.getElementById("verdict-text").textContent = isPhishing ? "⚠ PHISHING DETECTED" : "✓ LOOKS LEGITIMATE";
  document.getElementById("verdict-confidence").textContent =
    `${data.confidence}% confidence · phishing risk score ${data.phishing_risk_score}/100 · ${data.explanation.summary}`;

  const gaugeValue = document.getElementById("gauge-value");
  const circumference = 364.4;
  const offset = circumference - (data.phishing_risk_score / 100) * circumference;
  gaugeValue.style.strokeDashoffset = String(offset);
  gaugeValue.style.stroke = isPhishing ? "var(--rose)" : "var(--teal)";
  document.getElementById("gauge-number").textContent = `${Math.round(data.phishing_risk_score)}`;

  // --- Exhibit A: URL autopsy --------------------------------------------
  renderAutopsy(data.url);

  // --- Exhibit B: feature chips --------------------------------------------
  const grid = document.getElementById("feature-grid");
  grid.innerHTML = "";
  Object.entries(data.features).forEach(([key, value]) => {
    const chip = document.createElement("div");
    chip.className = "feature-chip";
    chip.innerHTML = `<span class="fc-label">${FEATURE_LABELS[key] || key}</span><span class="fc-value">${formatFeatureValue(key, value)}</span>`;
    grid.appendChild(chip);
  });

  // --- Exhibit C: SHAP explanation bars --------------------------------------
  const shapList = document.getElementById("shap-list");
  shapList.innerHTML = "";
  const maxAbs = Math.max(...data.explanation.top_features.map((f) => Math.abs(f.shap_value)), 0.0001);
  data.explanation.top_features.forEach((f) => {
    const row = document.createElement("div");
    row.className = "shap-row";
    const pct = (Math.abs(f.shap_value) / maxAbs) * 50; // half-track each direction
    const isPos = f.shap_value >= 0;
    row.innerHTML = `
      <span class="sr-label">${FEATURE_LABELS[f.feature] || f.feature}</span>
      <div class="sr-bar-track">
        <div class="sr-bar ${isPos ? "sr-bar--pos" : "sr-bar--neg"}"
             style="width:${pct}%; ${isPos ? "left:50%;" : `left:${50 - pct}%;`}"></div>
      </div>
      <p class="sr-text">${f.explanation}</p>
    `;
    shapList.appendChild(row);
  });

  resultsSection.scrollIntoView({ behavior: "smooth", block: "start" });
}

function formatFeatureValue(key, value) {
  if (["has_ip", "has_https", "has_at_symbol", "is_shortened", "suspicious_tld"].includes(key)) {
    return value ? "Yes" : "No";
  }
  return value;
}

/** Renders Exhibit A: the URL as monospace text with per-character tags. */
function renderAutopsy(url) {
  const container = document.getElementById("autopsy");
  container.innerHTML = "";
  const lowered = url.toLowerCase();

  const kwRanges = [];
  SUSPICIOUS_KEYWORDS.forEach((kw) => {
    let idx = lowered.indexOf(kw);
    while (idx !== -1) {
      kwRanges.push([idx, idx + kw.length]);
      idx = lowered.indexOf(kw, idx + 1);
    }
  });
  const inKeyword = (i) => kwRanges.some(([start, end]) => i >= start && i < end);

  const frag = document.createDocumentFragment();
  for (let i = 0; i < url.length; i++) {
    const ch = url[i];
    const span = document.createElement("span");
    span.className = "ch";
    span.textContent = ch;

    if (inKeyword(i)) span.classList.add("ch--kw");
    else if (ch === ".") span.classList.add("ch--dot");
    else if (ch === "-") span.classList.add("ch--hyphen");
    else if (ch === "@") span.classList.add("ch--at");
    else if (/[0-9]/.test(ch)) span.classList.add("ch--digit");

    frag.appendChild(span);
  }
  container.appendChild(frag);
}

/** Phase 5 + 6: fetch domain intelligence + VirusTotal after the ML verdict. */
async function loadSupplementaryPanels(url) {
  const intelBody = document.getElementById("domain-intel-body");
  intelBody.innerHTML = `<p class="muted">Looking up WHOIS registration data…</p>`;

  fetch("/api/domain-intel", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  })
    .then((r) => r.json())
    .then((d) => renderDomainIntel(d))
    .catch(() => {
      intelBody.innerHTML = `<p class="muted">Domain intelligence unavailable.</p>`;
    });

  const vtPanel = document.getElementById("vt-panel");
  const vtBody = document.getElementById("vt-body");
  fetch("/api/virustotal", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url }),
  })
    .then((r) => r.json())
    .then((d) => {
      if (!d.available) {
        vtPanel.hidden = true; // gracefully hide when no API key / no result
        return;
      }
      vtPanel.hidden = false;
      renderVirusTotal(d);
    })
    .catch(() => {
      vtPanel.hidden = true;
    });
}

function renderDomainIntel(d) {
  const body = document.getElementById("domain-intel-body");
  if (!d.available) {
    body.innerHTML = `<p class="muted">${escapeHtml(d.reason || "WHOIS data unavailable for this domain.")}</p>`;
    return;
  }
  const ageText = d.domain_age_days != null ? `${d.domain_age_days.toLocaleString()} days` : "Unknown";
  body.innerHTML = `
    <dl>
      <dt>Domain</dt><dd>${escapeHtml(d.hostname || "—")}</dd>
      <dt>Registrar</dt><dd>${escapeHtml(d.registrar || "Unknown")}</dd>
      <dt>Created</dt><dd>${escapeHtml(d.creation_date || "Unknown")}</dd>
      <dt>Expires</dt><dd>${escapeHtml(d.expiration_date || "Unknown")}</dd>
      <dt>Domain age</dt><dd>${ageText}</dd>
      <dt>Country</dt><dd>${escapeHtml(d.country || "Unknown")}</dd>
    </dl>
  `;
}

function renderVirusTotal(d) {
  const body = document.getElementById("vt-body");
  body.innerHTML = `
    <div class="vt-summary">
      <div class="vt-stat"><div class="vs-value" style="color:var(--rose)">${d.malicious}</div><div class="vs-label">Malicious</div></div>
      <div class="vt-stat"><div class="vs-value" style="color:var(--amber)">${d.suspicious}</div><div class="vs-label">Suspicious</div></div>
      <div class="vt-stat"><div class="vs-value" style="color:var(--teal)">${d.harmless}</div><div class="vs-label">Harmless</div></div>
      <div class="vt-stat"><div class="vs-value">${d.undetected}</div><div class="vs-label">Undetected</div></div>
    </div>
    <p class="muted">${escapeHtml(d.recommendation)} (${d.total_vendors} vendors checked)</p>
  `;
}

async function loadHistory() {
  const res = await fetch("/api/history?limit=25");
  const rows = await res.json();
  const body = document.getElementById("history-body");

  if (!rows.length) {
    body.innerHTML = `<tr><td colspan="6" class="empty-row">No scans yet — analyze a URL above to open the first case.</td></tr>`;
  } else {
    body.innerHTML = rows
      .map((row) => `
        <tr>
          <td>${String(row.id).padStart(4, "0")}</td>
          <td class="url-cell" title="${escapeHtml(row.url)}">${escapeHtml(row.url)}</td>
          <td><span class="badge-pill badge-pill--${row.prediction}">${row.prediction}</span></td>
          <td>${Math.round(row.confidence * 100)}%</td>
          <td>${FEATURE_LABELS[row.top_feature] || row.top_feature || "—"}</td>
          <td>${row.scanned_at}</td>
        </tr>`)
      .join("");
  }

  updateActivityStats(rows);
}

/** Phase 4: "Recent Activity" mini-stats derived from the current history. */
function updateActivityStats(rows) {
  document.getElementById("act-total").textContent = rows.length;
  document.getElementById("act-phishing").textContent = rows.filter((r) => r.prediction === "phishing").length;
  document.getElementById("act-legit").textContent = rows.filter((r) => r.prediction === "legitimate").length;
  document.getElementById("act-last").textContent = rows.length ? rows[0].scanned_at : "—";
}

function escapeHtml(str) {
  const div = document.createElement("div");
  div.textContent = str == null ? "" : String(str);
  return div.innerHTML;
}

async function loadModelInfo() {
  const res = await fetch("/api/model-info");
  const grid = document.getElementById("model-info-grid");
  const dsGrid = document.getElementById("dataset-stats-grid");
  const tag = document.getElementById("model-tag");

  if (!res.ok) {
    grid.innerHTML = `<p class="muted">Model metrics unavailable. Run <code>python models/train_model.py</code>.</p>`;
    dsGrid.innerHTML = "";
    tag.textContent = "model offline";
    return;
  }

  const data = await res.json();
  const rf = data.random_forest;
  const lr = data.logistic_regression;
  tag.textContent = `RandomForest · ${(rf.accuracy * 100).toFixed(1)}% test accuracy`;

  grid.innerHTML = `
    <div class="model-stat"><div class="ms-value">${(rf.accuracy * 100).toFixed(1)}%</div><div class="ms-label">RF accuracy</div></div>
    <div class="model-stat"><div class="ms-value">${(rf.f1_score * 100).toFixed(1)}%</div><div class="ms-label">RF F1 score</div></div>
    <div class="model-stat"><div class="ms-value">${(rf.roc_auc * 100).toFixed(1)}%</div><div class="ms-label">RF ROC-AUC</div></div>
    <div class="model-stat"><div class="ms-value">${(lr.accuracy * 100).toFixed(1)}%</div><div class="ms-label">Logistic Reg. accuracy</div></div>
  `;

  const stats = data.dataset_stats || {};
  dsGrid.innerHTML = `
    <div class="model-stat"><div class="ms-value">${(stats.total_urls || data.dataset_rows).toLocaleString()}</div><div class="ms-label">Training URLs</div></div>
    <div class="model-stat"><div class="ms-value">${(stats.phishing_urls ?? "—").toLocaleString?.() ?? stats.phishing_urls}</div><div class="ms-label">Phishing URLs</div></div>
    <div class="model-stat"><div class="ms-value">${(stats.legitimate_urls ?? "—").toLocaleString?.() ?? stats.legitimate_urls}</div><div class="ms-label">Legitimate URLs</div></div>
    <div class="model-stat"><div class="ms-value">${stats.avg_phishing_url_length ?? "—"}</div><div class="ms-label">Avg. phishing URL length</div></div>
    <div class="model-stat"><div class="ms-value">${stats.avg_legitimate_url_length ?? "—"}</div><div class="ms-label">Avg. legitimate URL length</div></div>
  `;
}

async function loadResearchInfo() {
  const body = document.getElementById("research-body");
  try {
    const res = await fetch("/api/research-info");
    const d = await res.json();
    if (!res.ok) throw new Error(d.error || "unavailable");

    body.innerHTML = `
      <h3>${escapeHtml(d.paper.title)}</h3>
      <p>${escapeHtml(d.paper.authors)} — <em>${escapeHtml(d.paper.venue)}</em>.
      <a href="${escapeHtml(d.paper.url)}" target="_blank" rel="noopener">DOI: ${escapeHtml(d.paper.doi)}</a></p>

      <h3>Key idea</h3>
      <p>${escapeHtml(d.key_idea)}</p>

      <h3>Research gap</h3>
      <p>${escapeHtml(d.research_gap)}</p>

      <h3>How PhishGuard AI extends it</h3>
      <p>${escapeHtml(d.how_this_extends_it)}</p>

      <h3>Future work</h3>
      <ul>${d.future_work.map((f) => `<li>${escapeHtml(f)}</li>`).join("")}</ul>
    `;
    body.dataset.loaded = "true";
  } catch (err) {
    body.innerHTML = `<p class="muted">Research context unavailable.</p>`;
  }
}

async function loadLexicon() {
  try {
    const res = await fetch("/api/lexicon");
    const d = await res.json();
    SUSPICIOUS_KEYWORDS = d.suspicious_keywords || [];
  } catch (err) {
    console.warn("Could not load lexicon, URL autopsy keyword highlighting disabled.", err);
  }
}

loadLexicon();
loadHistory();
loadModelInfo();
