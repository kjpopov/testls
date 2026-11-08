// Browser UI of `testls serve`. Plain script, no build step, no
// dependencies. Scanned values only ever reach the page through
// textContent and attributes set by DOM calls; markup is never parsed
// from strings.
"use strict";

// Values offered by the scan form; the server checks them again.
const STARTTLS = ["", "smtp", "imap", "pop3", "ftp", "xmpp", "ldap", "postgres", "mysql"];
const PROFILES = ["default", "quick", "full"];
const POLICIES = ["mozilla-modern", "mozilla-intermediate", "nist-800-52r2", "bsi-tr-02102-2", "pci-dss-4", "cnsa-2.0"];
const SEVERITIES = ["critical", "high", "medium", "low", "info"];
const FORMATS = ["text", "json", "html", "markdown", "csv", "sarif", "junit"];
const EXTENSIONS = { text: "txt", json: "json", html: "html", markdown: "md", csv: "csv", sarif: "sarif", junit: "xml" };

// Sections in the order a scan reports them, with display names.
const SECTIONS = [
  ["protocols", "Protocols"],
  ["ciphers", "Cipher suites"],
  ["key_exchange", "Key exchange"],
  ["post_quantum", "Post-quantum"],
  ["certificate", "Certificate"],
  ["revocation", "Revocation"],
  ["http", "HTTP headers"],
  ["vulnerabilities", "Vulnerabilities"],
  ["intolerance", "Tolerance"],
  ["details", "Handshake details"],
];

const DAY = 86400;
const $ = (id) => document.getElementById(id);

const state = {
  token: sessionStorage.getItem("testls-token"),
  current: null, // id of the scan on screen
  scan: null, // last GET /scans/{id} body
  view: null, // AbortController of the scan view's requests and stream
  filter: null, // severity selected in the stats strip
  explaining: null, // AbortController of the open explanation request
  opener: null, // element that had focus before the drawer opened
};

// Creates an element with optional class and text.
function el(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined && text !== null) node.textContent = String(text);
  return node;
}

// Replaces the children of `node`.
function fill(node, ...children) {
  node.replaceChildren(...children);
}

// Calls the API, asking for a token when the service wants one. Returns the
// response; throws an Error with the server's message otherwise.
async function api(path, options = {}) {
  const headers = new Headers(options.headers || {});
  if (state.token) headers.set("Authorization", `Bearer ${state.token}`);
  const response = await fetch(path, { ...options, headers, cache: "no-store" });
  if (response.status === 401) {
    $("token-button").hidden = false;
    askToken();
    throw new Error("the service needs a bearer token");
  }
  if (!response.ok) {
    let message = `${response.status} ${response.statusText}`;
    try {
      const body = await response.json();
      if (body && body.error) message = body.error;
    } catch (_) {
      // not JSON; keep the status line
    }
    throw new Error(message);
  }
  return response;
}

// Opens the token dialog.
function askToken() {
  const dialog = $("token-dialog");
  if (!dialog.open) dialog.showModal();
}

// Formats Unix seconds as a local date and time.
function when(seconds) {
  return new Date(seconds * 1000).toLocaleString();
}

// Formats Unix seconds as a local date.
function day(seconds) {
  return new Date(seconds * 1000).toLocaleDateString();
}

// A status or severity pill.
function pill(kind, text) {
  return el("span", `pill ${kind}`, text || kind);
}

// Fills the form's choices.
function setupForm() {
  const starttls = $("starttls");
  for (const value of STARTTLS) {
    const option = el("option", null, value || "none");
    option.value = value;
    starttls.append(option);
  }
  const profile = $("profile");
  for (const value of PROFILES) {
    const option = el("option", null, value);
    option.value = value;
    profile.append(option);
  }
  const policies = $("policies");
  for (const value of POLICIES) {
    const label = el("label", "check");
    const box = el("input");
    box.type = "checkbox";
    box.value = value;
    label.append(box, ` ${value}`);
    policies.append(label);
  }
  $("scan-form").addEventListener("submit", startScan);
}

// Sends the scan form.
async function startScan(event) {
  event.preventDefault();
  const button = $("scan-button");
  $("form-error").textContent = "";
  const body = {
    target: $("target").value.trim(),
    profile: $("profile").value,
    revocation: $("revocation").checked,
    policies: [...$("policies").querySelectorAll("input:checked")].map((b) => b.value),
  };
  if ($("starttls").value) body.starttls = $("starttls").value;
  if ($("sni").value.trim()) body.sni = $("sni").value.trim();
  button.disabled = true;
  try {
    const response = await api("/scans", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
    });
    const started = await response.json();
    location.hash = `#${started.id}`;
    refreshHistory();
  } catch (e) {
    $("form-error").textContent = e.message;
  } finally {
    button.disabled = false;
  }
}

// Reloads the history sidebar.
async function refreshHistory() {
  let scans;
  try {
    scans = await (await api("/scans")).json();
  } catch (e) {
    $("status-line").textContent = e.message;
    return;
  }
  $("status-line").textContent = "";
  const list = $("history");
  fill(list);
  $("history-empty").hidden = scans.length > 0;
  for (const scan of scans) {
    const item = el("a", "group-item");
    item.href = `#${scan.id}`;
    if (scan.id === state.current) item.classList.add("active");
    const top = el("div", "group-top");
    top.append(el("span", "group-name", scan.target));
    if (scan.grade) top.append(el("span", `grade-small ${gradeClass(scan.grade)}`, scan.grade));
    else top.append(pill(statusClass(scan.status), scan.status));
    item.append(top, el("div", "group-meta", when(scan.created_at)));
    list.append(item);
  }
}

// CSS class of a scan status.
function statusClass(status) {
  return { running: "pending", done: "ok", failed: "error" }[status] || "pending";
}

// CSS class of a grade letter.
function gradeClass(letter) {
  if (letter.startsWith("A")) return "ok";
  if (letter === "B" || letter === "C") return "warn";
  return "crit";
}

// Shows the scan named in the URL fragment. Each call starts a new view;
// aborting the previous one cancels its requests and stream, so late
// answers for an earlier scan never reach the page.
async function route() {
  const id = Number(location.hash.slice(1));
  if (state.view) state.view.abort();
  const view = new AbortController();
  state.view = view;
  state.scan = null;
  state.filter = null;
  $("report").hidden = true;
  $("grade").hidden = true;
  if (!Number.isInteger(id) || id <= 0) {
    state.current = null;
    $("scan").hidden = true;
    $("welcome").hidden = false;
    refreshHistory();
    return;
  }
  state.current = id;
  $("welcome").hidden = true;
  $("scan").hidden = false;
  fill($("scan-target"), `scan ${id}`);
  fill($("scan-meta"));
  $("scan-error").hidden = true;
  refreshHistory();
  await watch(id, view.signal);
}

// Waits `ms` milliseconds unless `signal` aborts first.
function pause(ms, signal) {
  return new Promise((resolve) => {
    const timer = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      clearTimeout(timer);
      resolve();
    }, { once: true });
  });
}

// Loads scan `id` and follows its progress until it ends or the view
// changes. A dropped or refused stream is retried with growing delays.
async function watch(id, signal) {
  let delay = 1000;
  while (!signal.aborted) {
    let scan;
    try {
      scan = await (await api(`/scans/${id}`, { signal })).json();
    } catch (e) {
      if (signal.aborted) return;
      showScan({ id, target: `scan ${id}`, status: "failed", error: e.message, sections: [], header: "" });
      return;
    }
    if (signal.aborted) return;
    showScan(scan);
    if (scan.status !== "running") {
      refreshHistory();
      return;
    }
    const ended = await follow(scan, signal);
    if (signal.aborted) return;
    if (!ended) {
      await pause(delay, signal);
      delay = Math.min(delay * 2, 30000);
    }
  }
}

// Reads the progress stream of a running scan into `scan`. EventSource
// cannot send the bearer token, so the stream is read through fetch.
// Returns true when the final event arrived, false when the stream failed
// or ended early.
async function follow(scan, signal) {
  const seen = scan.sections.length;
  const headers = seen > 0 ? { "Last-Event-ID": String(seen - 1) } : {};
  try {
    const response = await api(`/scans/${scan.id}/events`, { headers, signal });
    const reader = response.body.pipeThrough(new TextDecoderStream()).getReader();
    let buffer = "";
    for (;;) {
      const { value, done } = await reader.read();
      if (done) return false;
      buffer += value;
      // Normalise line ends, keeping a trailing CR until the next chunk
      // shows whether an LF follows.
      const tail = buffer.endsWith("\r") ? "\r" : "";
      buffer = buffer.slice(0, buffer.length - tail.length).replace(/\r\n?/g, "\n");
      let end;
      while ((end = buffer.indexOf("\n\n")) >= 0) {
        const block = buffer.slice(0, end);
        buffer = buffer.slice(end + 2);
        if (signal.aborted) return true;
        if (onEvent(scan, block)) {
          reader.cancel().catch(() => {});
          return true;
        }
      }
      buffer += tail;
    }
  } catch (e) {
    if (!signal.aborted) $("status-line").textContent = `progress stream: ${e.message}`;
    return false;
  }
}

// Handles one server-sent event block for `scan`. Returns true after the
// final event.
function onEvent(scan, block) {
  let name = "message";
  const data = [];
  for (const line of block.split("\n")) {
    if (line.startsWith(":")) continue;
    const colon = line.indexOf(":");
    const field = colon < 0 ? line : line.slice(0, colon);
    const value = colon < 0 ? "" : line.slice(colon + 1).replace(/^ /, "");
    if (field === "event") name = value;
    else if (field === "data") data.push(value);
  }
  if (name === "section" && data.length) {
    scan.sections.push(JSON.parse(data.join("\n")));
    showProgress(scan);
    return false;
  }
  return name === "done";
}

// Renders a scan.
function showScan(scan) {
  state.scan = scan;
  $("scan-target").textContent = scan.target;
  const meta = [];
  if (scan.created_at) meta.push(`requested ${when(scan.created_at)}`);
  if (scan.report && scan.report.target) {
    meta.push(scan.report.target.address);
    if (scan.report.target.sni) meta.push(`SNI ${scan.report.target.sni}`);
  }
  $("scan-meta").textContent = meta.join(" · ");
  const status = $("scan-state");
  status.className = `pill ${statusClass(scan.status)}`;
  status.textContent = scan.status;
  $("scan-error").hidden = !scan.error;
  $("scan-error").textContent = scan.error || "";
  showProgress(scan);
  const report = scan.report;
  $("report").hidden = !report;
  $("grade").hidden = !report;
  if (report) showReport(scan.id, report);
}

// Renders the section checklist, the progress bar and the text output.
function showProgress(scan) {
  const seen = new Set(scan.sections.map((s) => s.section));
  const running = scan.status === "running";
  const list = $("progress-list");
  fill(list);
  let last = -1;
  SECTIONS.forEach(([key], i) => {
    if (seen.has(key)) last = i;
  });
  SECTIONS.forEach(([key, label], i) => {
    let kind = "pending";
    if (seen.has(key)) kind = "ok";
    else if (!running || i < last) kind = "skipped";
    const item = el("span", `step ${kind}`, label);
    if (running && kind === "pending" && i === last + 1) item.classList.add("current");
    list.append(item);
  });
  const done = running ? Math.min(last + 1, SECTIONS.length - 1) : SECTIONS.length;
  $("progress-bar").style.width = `${Math.round((done / SECTIONS.length) * 100)}%`;
  $("progress").hidden = !running && scan.status === "done";
  const text = [scan.header || ""];
  for (const s of scan.sections) text.push(s.text);
  $("text").textContent = text.join("\n");
}

// Renders the finished report of scan `id`.
function showReport(id, report) {
  const grade = $("grade");
  grade.className = `grade ${gradeClass(report.grade.letter)}`;
  grade.textContent = report.grade.letter;
  grade.title = [
    report.grade.untrusted ? "certificate not trusted" : "",
    report.grade.incomplete ? "incomplete scan" : "",
  ].filter(Boolean).join(", ");
  if (report.grade.untrusted) grade.append(el("sup", null, "T"));
  showStats(report.findings);
  showFindings();
  showCertificate(report.certificate);
  showProtocols(report);
  showVulnerabilities(report.vulnerabilities);
  const reasons = $("reasons");
  fill(reasons);
  for (const reason of report.grade.reasons) reasons.append(el("li", null, reason));
  if (!report.grade.reasons.length) reasons.append(el("li", "dim", "Nothing holds the grade back."));
  showExport(id);
}

// Renders the severity counts; a click filters the findings table.
function showStats(findings) {
  const strip = $("stats");
  fill(strip);
  const cells = [["all", "Findings", findings.length]];
  for (const severity of SEVERITIES) {
    cells.push([severity, severity, findings.filter((f) => f.severity === severity).length]);
  }
  for (const [key, label, count] of cells) {
    const cell = el("button", `stat-cell sev-${key}`);
    cell.type = "button";
    if ((state.filter || "all") === key) cell.classList.add("active");
    cell.append(el("div", "stat-label", label), el("div", "stat-value", count));
    cell.addEventListener("click", () => {
      state.filter = key === "all" ? null : key;
      showStats(findings);
      showFindings();
    });
    strip.append(cell);
  }
}

// Renders the findings table with the current filter, search and order.
function showFindings() {
  const findings = (state.scan && state.scan.report && state.scan.report.findings) || [];
  const query = $("search").value.trim().toLowerCase();
  const rank = (s) => SEVERITIES.indexOf(s);
  const rows = findings
    .filter((f) => !state.filter || f.severity === state.filter)
    .filter((f) => !query || f.id.includes(query) || f.message.toLowerCase().includes(query))
    .sort((a, b) => ($("sort").value === "id" ? a.id.localeCompare(b.id) : rank(a.severity) - rank(b.severity)));
  const body = $("findings");
  fill(body);
  for (const f of rows) {
    const row = el("tr", "finding");
    row.tabIndex = 0;
    const severity = el("td");
    severity.append(pill(`sev-${f.severity}`, f.severity));
    row.append(severity, el("td", "mono", f.id), el("td", null, f.message));
    row.addEventListener("click", () => explain(f));
    row.addEventListener("keydown", (e) => {
      if (e.key === "Enter") explain(f);
    });
    body.append(row);
  }
  $("findings-empty").hidden = rows.length > 0;
}

// A key-value grid from [key, value] pairs, skipping empty values.
function grid(pairs) {
  const node = el("div", "kv-grid");
  for (const [key, value] of pairs) {
    if (value === undefined || value === null || value === "") continue;
    node.append(el("div", "kv-key", key));
    const cell = el("div", "kv-value");
    if (value instanceof Node) cell.append(value);
    else cell.textContent = String(value);
    node.append(cell);
  }
  return node;
}

// Renders the leaf certificate with its expiry bar and the rest of the chain.
function showCertificate(cert) {
  const box = $("certificate");
  fill(box);
  if (cert.error) {
    box.append(el("div", "dim", cert.error));
    return;
  }
  const [leaf, ...rest] = cert.chain;
  if (!leaf || leaf.error) {
    box.append(el("div", "dim", (leaf && leaf.error) || "no certificate"));
    return;
  }
  box.append(expiry(leaf));
  const names = el("div", "san-list");
  for (const name of leaf.names || []) names.append(el("span", "san-tag", name));
  let ocsp = "not stapled";
  if (cert.ocsp && cert.ocsp.stapled) ocsp = `stapled, ${cert.ocsp.status}`;
  if (!cert.ocsp) ocsp = null;
  box.append(grid([
    ["Subject", leaf.subject],
    ["Issuer", leaf.issuer],
    ["Valid", `${day(leaf.not_before)} – ${day(leaf.not_after)}`],
    ["Key", leaf.key],
    ["Names", names],
    ["SCTs", leaf.scts],
    ["OCSP", ocsp],
    ["Chain", rest.map((c) => c.subject || c.error).join(" → ") || "leaf only"],
  ]));
}

// Days left on the leaf certificate with a bar of the elapsed lifetime.
function expiry(leaf) {
  const now = Date.now() / 1000;
  const left = Math.floor((leaf.not_after - now) / DAY);
  const total = Math.max(leaf.not_after - leaf.not_before, 1);
  const used = Math.min(Math.max((now - leaf.not_before) / total, 0), 1);
  let kind = "ok";
  if (left < 0) kind = "crit";
  else if (left < 14) kind = "crit";
  else if (left < 30) kind = "warn";
  const node = el("div", "expiry");
  const days = el("div", `drawer-expiry ${kind}`);
  days.append(el("span", "days", Math.abs(left)), el("span", "days-label", left < 0 ? "days expired" : "days left"));
  const track = el("div", "bar-track");
  const bar = el("div", `bar-fill ${kind}`);
  bar.style.width = `${Math.round(used * 100)}%`;
  track.append(bar);
  node.append(days, track);
  return node;
}

// Renders protocol support with the suites of each offered version.
function showProtocols(report) {
  const box = $("protocols");
  fill(box);
  const table = el("table", "plain");
  for (const p of report.protocols) {
    const row = el("tr");
    const status = el("td");
    const kind = { offered: p.version === "TLSv1.3" || p.version === "TLSv1.2" ? "ok" : "crit", not_offered: "pending", error: "error" }[p.status];
    status.append(pill(kind, p.status.replace("_", " ")));
    const ciphers = report.ciphers.find((c) => c.protocol === p.version);
    const suites = el("td", "suites");
    if (ciphers && ciphers.error) suites.append(el("span", "dim", ciphers.error));
    else if (ciphers) {
      for (const s of ciphers.suites) suites.append(el("span", `suite sev-${s.severity}`, s.name));
      if (ciphers.order) suites.append(el("span", "dim", ` ${ciphers.order} order`));
    }
    row.append(el("td", "mono", p.version), status, suites);
    table.append(row);
  }
  box.append(table);
  const pq = report.post_quantum;
  if (pq && pq.status !== "not tested") {
    box.append(grid([["Post-quantum", `${pq.status}${pq.groups.length ? ` (${pq.groups.map((g) => g.name).join(", ")})` : ""}`]]));
  }
}

// Renders the named vulnerabilities, vulnerable ones first.
function showVulnerabilities(vulns) {
  const box = $("vulnerabilities");
  fill(box);
  const order = { vulnerable: 0, "not tested": 1, "not vulnerable": 2 };
  const table = el("table", "plain");
  for (const v of [...vulns].sort((a, b) => order[a.status] - order[b.status])) {
    const row = el("tr");
    const status = el("td");
    const kind = { vulnerable: "crit", "not vulnerable": "ok", "not tested": "pending" }[v.status];
    status.append(pill(kind, v.status));
    row.append(el("td", null, v.name), status, el("td", "dim", v.detail));
    table.append(row);
  }
  box.append(table);
}

// Renders the export buttons for scan `id`.
function showExport(id) {
  const box = $("export");
  fill(box);
  for (const format of FORMATS) {
    const button = el("button", "ghost", format);
    button.type = "button";
    button.addEventListener("click", () => download(id, format));
    box.append(button);
  }
}

// Downloads the report of scan `id` in `format`. Fetched rather than
// linked so the token can be sent.
async function download(id, format) {
  try {
    const blob = await (await api(`/scans/${id}/report?format=${format}`)).blob();
    const url = URL.createObjectURL(blob);
    const link = el("a");
    link.href = url;
    link.download = `testls-${id}.${EXTENSIONS[format]}`;
    document.body.append(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  } catch (e) {
    $("status-line").textContent = `export: ${e.message}`;
  }
}

// Opens the drawer with the explanation of a finding. A newer request
// cancels an older one, so only the shown finding's text arrives.
async function explain(finding) {
  if (state.explaining) state.explaining.abort();
  const request = new AbortController();
  state.explaining = request;
  $("drawer-title").textContent = finding.id;
  const body = $("drawer-body");
  const head = () => [pill(`sev-${finding.severity}`, finding.severity), el("p", null, finding.message)];
  fill(body, ...head(), el("div", "spinner"));
  const drawer = $("drawer");
  if (!drawer.open) drawer.showModal();
  try {
    const path = `/explanations/${encodeURIComponent(finding.id)}`;
    const e = await (await api(path, { signal: request.signal })).json();
    if (request.signal.aborted) return;
    fill(body, ...head(), el("h4", null, e.title), el("p", null, e.rationale), grid([["Reference", e.reference]]));
  } catch (err) {
    if (!request.signal.aborted) fill(body, ...head(), el("p", "dim", err.message));
  }
}

// Closes the drawer; the browser returns focus to the finding row.
function closeDrawer() {
  if (state.explaining) state.explaining.abort();
  $("drawer").close();
}

// Wires up the page.
function init() {
  setupForm();
  $("search").addEventListener("input", showFindings);
  $("sort").addEventListener("change", showFindings);
  const drawer = $("drawer");
  $("drawer-close").addEventListener("click", closeDrawer);
  // A click on the backdrop lands on the dialog element itself.
  drawer.addEventListener("click", (e) => {
    if (e.target === drawer) closeDrawer();
  });
  drawer.addEventListener("cancel", () => {
    if (state.explaining) state.explaining.abort();
  });
  $("token-button").addEventListener("click", askToken);
  if (state.token) $("token-button").hidden = false;
  $("token-form").addEventListener("submit", () => {
    state.token = $("token").value.trim() || null;
    if (state.token) sessionStorage.setItem("testls-token", state.token);
    else sessionStorage.removeItem("testls-token");
    $("token").value = "";
    route();
  });
  window.addEventListener("hashchange", route);
  route();
}

init();
