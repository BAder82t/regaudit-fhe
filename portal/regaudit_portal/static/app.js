"use strict";

// Everything from the server is shown with textContent. The page shows the verdict it receives and never works one out.

const $ = (id) => document.getElementById(id);
const CHOOSE = "Drop a report file (.json) here, or click to choose one";
const LIMIT = 1048576;
let chosen = null;
let lastSaved = null;
let ownReady = false; // can the administrator's policy check an uploaded report?
let lastView = "welcome"; // where "Check another report" goes back to
const VIEWS = ["welcome", "samples", "upload", "not-ready"];

function show(id, visible) {
  $(id).hidden = !visible;
}

// The engine is missing or failed its check: nothing can be verified or saved until the administrator fixes it.
function unavailable() {
  for (const view of VIEWS) show(view, false);
  show("result", false);
  show("batch-result", false);
  show("failure", false);
  show("record-notice", false);
  show("saved", false);
  show("unavailable", true);
  // Nothing that names the engine, the policy or a result may stay on screen once the engine has stopped passing.
  for (const id of ["policy", "claim", "engine-summary", "engine-scope", "check-key", "raw", "verdict", "result-file", "demo-banner", "demo-label", "trust-mode"]) {
    $(id).textContent = "";
  }
  $("sample-list").replaceChildren();
  $("batch-rows").replaceChildren();
  $("batch-summary").textContent = "";
  lastBatch = null;
  $("verdict").removeAttribute("data-status");
  $("result").classList.remove("demonstration");
  chosen = null;
  lastSaved = null;
}

// One screen at a time: the start, the samples, uploading your own report, or the note that your own reports are not set up.
function showView(name) {
  const view = name === "own" ? (ownReady ? "upload" : "not-ready") : name;
  for (const each of VIEWS) show(each, each === view);
  show("failure", false);
  show("result", false);
  show("batch-result", false);
  show("saved", false);
  if (name === "welcome" || name === "samples" || name === "own") lastView = name;
}

function fail(message) {
  $("failure-message").textContent = message;
  show("failure", true);
  show("result", false);
}

function choose(file) {
  chosen = file || null;
  lastSaved = null;
  $("drop-text").textContent = chosen ? "Selected: " + chosen.name : CHOOSE;
  $("verify").disabled = !chosen;
  show("failure", false);
  show("result", false);
  show("saved", false);
}

function readableTime(value) {
  const moment = new Date(value);
  if (Number.isNaN(moment.getTime())) return value;
  const months = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"];
  const pad = (n) => String(n).padStart(2, "0");
  return moment.getUTCDate() + " " + months[moment.getUTCMonth()] + " " + moment.getUTCFullYear() + ", " +
    pad(moment.getUTCHours()) + ":" + pad(moment.getUTCMinutes()) + " UTC";
}

// The five separate statements about a result, in a fixed order with fixed labels. Each state the portal can return has
// fixed plain words that say what was found and nothing more: "In your administrator's list" is not "trusted", "Matches"
// is not "authentic". A state the page does not know is shown as the portal sent it and marked as not interpreted, so
// the page never invents a conclusion. The verdict above stays the verifier's own word.
const STATEMENTS = [
  ["signature", "Signature", {
    passed: "Matches the contents", failed: "Does not match the contents", not_checked: "Not checked",
  }],
  ["issuer_trust", "Issuer", {
    established: "In your administrator's list",
    established_with_limit: "In your administrator's list, with a limit (read the text)",
    not_established: "Not in your administrator's list",
  }],
  ["freshness", "Age", {
    within_limit: "Within the maximum age", too_old: "Older than the maximum age",
    from_future: "Dated in the future", not_checked: "Not checked",
  }],
  ["replay", "Repeat check", {
    repeat_detected: "Seen before", state_unavailable: "The repeat check was unavailable",
    recorded: "Recorded as seen", checked_not_seen: "Not seen before (not recorded)", not_checked: "Not checked",
  }],
  ["encryption_claims", "Encryption claims", {
    plaintext_stated: "Plaintext backend declared by the signer", declared_by_signer: "Declared by the signer, not verified",
    not_stated: "Not stated",
  }],
];

// Pure: from the portal's statuses member to the rows to show. No DOM, so it is tested exactly as it ships.
function statementRows(statuses) {
  if (!statuses || typeof statuses !== "object") return [];
  const rows = [];
  for (const [key, label, words] of STATEMENTS) {
    const entry = statuses[key];
    if (!entry || typeof entry !== "object") continue;
    const known = Object.prototype.hasOwnProperty.call(words, entry.state);
    rows.push({
      key: key,
      label: label,
      state: String(entry.state),
      stateText: known ? words[entry.state] : String(entry.state) + " (not interpreted by this page)",
      known: known,
      text: typeof entry.text === "string" ? entry.text : "",
      limit: typeof entry.limit === "string" ? entry.limit : "",
    });
  }
  return rows;
}

function renderStatements(statuses) {
  const list = $("statements");
  list.replaceChildren();
  const rows = statementRows(statuses);
  for (const row of rows) {
    const item = document.createElement("li");
    item.dataset.statement = row.key;
    item.dataset.state = row.state;
    const head = document.createElement("strong");
    head.textContent = row.label + ": ";
    const state = document.createElement("span");
    state.className = "statement-state";
    state.textContent = row.stateText;
    const text = document.createElement("p");
    text.textContent = row.text;
    item.append(head, state, text);
    if (row.limit) {
      const limit = document.createElement("p");
      limit.className = "fine";
      limit.textContent = row.limit;
      item.append(limit);
    }
    list.append(item);
  }
  show("statements-box", rows.length > 0);
}

function render(body, fileName) {
  const v = body.verification;
  const e = body.explanation;
  const verdict = $("verdict");
  verdict.textContent = v.trust_status;
  // The word itself is always the verifier's own.
  verdict.className = v.trust_status === "TRUSTED" ? "verdict trusted" : "verdict";
  verdict.dataset.status = v.trust_status; // the style picks its shape and colour from this, and never the wording
  const demonstration = body.synthetic_demonstration === true;
  $("result").classList.toggle("demonstration", demonstration);
  // A demonstration result carries one label, exactly as the portal wrote it, next to the verifier's own verdict,
  // which stays as it is.
  $("demo-label").textContent = demonstration ? body.demonstration_label : "";
  show("demo-label", demonstration);
  const banner = $("demo-banner");
  banner.replaceChildren();
  if (demonstration) {
    const label = document.createElement("strong");
    label.textContent = body.demonstration.label;
    banner.append(label, document.createElement("br"), body.demonstration.notice);
  }
  show("demo-banner", demonstration);
  $("result-file").textContent = fileName ? "Result for: " + fileName : "";
  $("verdict-meaning").textContent = e.verdict;
  $("verdict-means").textContent = e.means || "";
  show("verdict-means", Boolean(e.means));
  $("check-integrity").textContent = e.signature;
  $("check-issuer").textContent = e.issuer;
  $("check-key").textContent = v.key_status;
  // Text the signer controls is shown from the portal's own display copies, in which control and direction
  // characters are replaced by visible escapes. The saved result keeps the verifier's exact values.
  const d = e.display;
  $("check-issuer-name").textContent = d.issuer;
  $("check-issuer-note").textContent = d.issuer_note ? "(" + d.issuer_note + ")" : "";
  $("check-issued").textContent = readableTime(d.issued_at) + " (as stated by the signer)";

  const claims = body.encryption_declarations;
  $("enc-statement").textContent = claims.statement;
  $("enc-established").textContent = claims.established_statement;
  $("enc-invariant").textContent = claims.invariant;
  $("enc-backend").textContent = (claims.backend === null ? "none" : claims.backend + (claims.backend_shortened ? " (shortened)" : "")) + " (stated in the report)";
  $("enc-bits").textContent = claims.security_bits_text;
  $("enc-note").textContent = claims.note;
  $("engine-summary").textContent = body.engine.summary;
  $("engine-scope").textContent = body.engine.check_scope;

  const warnings = $("warnings");
  warnings.replaceChildren();
  for (const warning of e.warnings) {
    const item = document.createElement("li");
    item.textContent = warning.message;
    item.dataset.code = warning.code;
    warnings.append(item);
  }
  show("warnings-box", e.warnings.length > 0);

  const reasons = $("reasons");
  reasons.replaceChildren();
  for (const reason of e.reasons) {
    const row = document.createElement("tr");
    const code = document.createElement("code");
    code.textContent = reason.code;
    const cells = [reason.meaning, reason.blocking ? "Blocks acceptance" : "Note", code];
    for (const content of cells) {
      const cell = document.createElement("td");
      cell.append(content);
      row.append(cell);
    }
    reasons.append(row);
  }
  show("reasons-box", e.reasons.length > 0);
  renderStatements(body.statuses);

  $("raw").textContent = d.technical_details;
  show("failure", false);
  show("result", true);
  // Respect the reader's setting: no animated scroll when they have asked their system for less motion.
  const reduceMotion = window.matchMedia && window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  $("result").scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth", block: "nearest" });
}

async function verifyChosen() {
  if (!chosen) return;
  $("verify").disabled = true;
  show("failure", false);
  show("result", false);
  show("saved", false);
  try {
    if (chosen.size > LIMIT) {
      fail("This file is over the 1 MB limit. Nothing was verified, so treat it as not accepted. A signed report is usually much smaller, so check you chose the right file.");
      return;
    }
    const response = await fetch("/api/verify", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: await chosen.arrayBuffer(),
    });
    const body = JSON.parse(await response.text());
    if (body.state === "unavailable") {
      unavailable();
      return;
    }
    if (!response.ok || !body.verification) {
      fail(body.message || "The check could not be completed, so there is no verdict. Treat the report as not accepted.");
      return;
    }
    lastSaved = { body: body, name: chosen.name };
    lastView = "own";
    render(body, chosen.name);
  } catch (error) {
    fail("The check could not be completed, so there is no verdict. Treat the report as not accepted.");
  } finally {
    $("verify").disabled = !chosen;
  }
}

// A bundled sample, chosen from the list by its id. Nothing is uploaded and no report is sent: the portal reads its own copy.
async function checkSample(sample, button) {
  button.disabled = true;
  show("failure", false);
  show("result", false);
  show("saved", false);
  try {
    const response = await fetch("/api/samples/" + encodeURIComponent(sample.id) + "/verify", { method: "POST" });
    const body = JSON.parse(await response.text());
    if (body.state === "unavailable") {
      unavailable();
      return;
    }
    if (!response.ok || !body.verification) {
      fail(body.message || "The check could not be completed, so there is no verdict.");
      return;
    }
    lastSaved = { body: body, name: "sample-" + sample.id };
    lastView = "samples";
    render(body, "sample: " + sample.title);
  } catch (error) {
    fail("The check could not be completed, so there is no verdict.");
  } finally {
    button.disabled = false;
  }
}

function listSamples(samples) {
  const list = $("sample-list");
  list.replaceChildren();
  for (const sample of samples) {
    const item = document.createElement("li");
    const title = document.createElement("strong");
    title.textContent = sample.title;
    const text = document.createElement("p");
    text.className = "fine";
    text.textContent = sample.description;
    const button = document.createElement("button");
    button.type = "button";
    button.textContent = "Check this sample";
    button.addEventListener("click", () => checkSample(sample, button));
    item.append(title, text, button);
    list.append(item);
  }
}

// May this result be saved now, given what the portal says about itself at this moment? Nothing is saved unless the
// engine passes its check. A demonstration sample needs nothing more, because it is checked against the bundled
// demonstration policy. A result for your own report also needs the administrator's policy to be loaded.
function savePermitted(status, result) {
  if (status.state === "unavailable" || !status.engine) return false;
  return result.synthetic_demonstration === true || status.ready === true;
}

async function download() {
  if (lastSaved === null) return;
  // The engine is checked again here, so no saved result is produced unless it passes at this moment.
  const status = await (await fetch("/api/status")).json();
  if (!savePermitted(status, lastSaved.body)) {
    if (status.state === "unavailable") unavailable();
    else fail("This portal cannot save a result right now. Contact your administrator.");
    return;
  }
  const stem = lastSaved.name.replace(/\.json$/i, "").replace(/[^A-Za-z0-9._-]+/g, "-").slice(0, 80) || "report";
  const kind = lastSaved.body.synthetic_demonstration === true ? "demonstration-result-" : "verification-result-";
  const fileName = kind + stem + "-" + lastSaved.body.report_sha256.slice(0, 12) + ".json";
  const saved = Object.assign({ report_file_name: lastSaved.name }, lastSaved.body);
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([JSON.stringify(saved, null, 2) + "\n"], { type: "application/json" }));
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(link.href);
  $("saved").textContent = "Saved to your downloads as " + fileName;
  show("saved", true);
}

// ---- Several reports at once ---------------------------------------------------------------------------------------------
// Each file is checked exactly as a single upload is, by the same portal function, and each gets its own result. The page
// plans the batch against the portal's stated limits before sending anything, sends it as one bounded request, shows one
// row per file with the verifier's own verdict, and checks that what it would save is consistent before it saves it.
const BATCH_SCHEMA = "regaudit-portal-batch/1";
const BATCH_FALLBACK = { max_files: 20, max_file_bytes: 1048576, max_total_bytes: 8388608 };
// The page does not list the verifier's verdict words: it never decides one. It only checks that a verdict is word-shaped.
const VERDICT_SHAPE = /^[A-Z][A-Z_]{1,63}$/;
let lastBatch = null;
let batchAbort = null;

function batchLimits(status) {
  const given = status && status.batch;
  if (!given) return BATCH_FALLBACK;
  const pick = (k) => (Number.isInteger(given[k]) && given[k] > 0 ? given[k] : BATCH_FALLBACK[k]);
  return { max_files: pick("max_files"), max_file_bytes: pick("max_file_bytes"), max_total_bytes: pick("max_total_bytes") };
}

// Pure. Whether these files may be sent at all. All or nothing, as the portal itself does: a batch that is over a limit
// is refused whole, and the message says which limit and by how much, so the person can send smaller groups.
// Pure. A file name as it can safely be shown in a message: only the last part of any path (never a folder), no control or
// direction-changing characters, and at most 60 characters. The page puts it in with textContent, so it is never read as markup either.
function shownName(name) {
  let text = String(name === null || name === undefined ? "" : name);
  text = text.slice(Math.max(text.lastIndexOf("/"), text.lastIndexOf("\\")) + 1);
  text = text.replace(/[\u0000-\u001f\u007f-\u009f\u00ad\u061c\u180e\u200b-\u200f\u2028-\u202e\u2060-\u2069\ufeff\ufff9-\ufffb]/g, "");
  text = text.trim();
  if (text === "") return "(unnamed)";
  return text.length > 60 ? text.slice(0, 57) + "..." : text;
}

function planBatch(files, limits) {
  if (!files || files.length === 0) return { ok: false, message: "Choose at least one report file." };
  if (files.length > limits.max_files) {
    return { ok: false, message: "A batch can hold at most " + limits.max_files + " files and " + files.length + " were chosen. Nothing was verified. Send the files in smaller groups." };
  }
  const tooBig = files.filter((file) => file.size > limits.max_file_bytes);
  if (tooBig.length > 0) {
    const more = tooBig.length > 1 ? " and " + (tooBig.length - 1) + " more" : "";
    return { ok: false, message: 'The file "' + shownName(tooBig[0].name) + '"' + more + (tooBig.length > 1 ? " are" : " is") + " over the " + Math.floor(limits.max_file_bytes / 1048576) + " MB limit. Nothing was verified. Take " + (tooBig.length > 1 ? "them" : "it") + " out of the batch or send " + (tooBig.length > 1 ? "them on their own." : "it on its own.") };
  }
  let total = 0;
  for (const file of files) total += file.size;
  if (total > limits.max_total_bytes) {
    return { ok: false, message: "The files together are over the " + Math.floor(limits.max_total_bytes / 1048576) + " MB limit for a batch. Nothing was verified. Send the files in smaller groups." };
  }
  return { ok: true, message: "" };
}

function toBase64(bytes) {
  let text = "";
  for (let i = 0; i < bytes.length; i += 0x8000) text += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000));
  return btoa(text);
}

// Pure. The request body, exactly as the portal expects it, and nothing else.
function batchRequestBody(entries) {
  return JSON.stringify({ files: entries.map((e) => ({ name: e.name, content_b64: toBase64(e.bytes) })) });
}

// Pure. One row per file, in the order the portal answered. The verdict is the verifier's word for that file, unchanged;
// a file the portal could not check has no verdict and says why.
function batchRows(answer) {
  const rows = [];
  for (const file of (answer && Array.isArray(answer.files)) ? answer.files : []) {
    const base = { id: String(file.id), name: String(file.name), ok: file.ok === true };
    if (file.ok === true && file.result && file.result.verification) {
      rows.push(Object.assign(base, {
        verdict: String(file.result.verification.trust_status),
        statements: statementRows(file.result.statuses),
        message: "",
      }));
    } else {
      const error = file.error || {};
      rows.push(Object.assign(base, { verdict: null, statements: [], message: String(error.message || "No verdict.") }));
    }
  }
  return rows;
}

// Pure. Is this batch answer consistent with itself and with the single-file results it contains? It returns a list of
// problems; an empty list means nothing contradicts anything. It does not re-verify any report: the verdicts are the
// verifier's and stay as they are. What it refuses to pass on is an answer whose parts do not agree, such as a count that
// does not match the files, a verdict word the verifier does not use, or statements that contradict the verdict.
function validateBatch(answer) {
  const problems = [];
  if (!answer || typeof answer !== "object" || answer.schema !== BATCH_SCHEMA) return ["not a batch result of this portal"];
  if (!Array.isArray(answer.files) || !answer.summary) return ["the batch result has no files or no summary"];
  let trusted = 0, notAccepted = 0, refused = 0, notRun = 0;
  answer.files.forEach((file, index) => {
    const where = "file " + (index + 1);
    if (file.index !== index || file.id !== "file-" + (index + 1)) problems.push(where + ": out of order or mislabelled");
    if (file.ok === true) {
      const v = file.result && file.result.verification;
      if (!v || typeof v.trust_status !== "string" || !VERDICT_SHAPE.test(v.trust_status)) { problems.push(where + ": no verdict word"); return; }
      if (file.error) problems.push(where + ": has both a result and an error");
      if (typeof file.report_sha256 !== "string" || file.report_sha256.length !== 64) problems.push(where + ": no report digest");
      const s = file.result.statuses;
      if (s && s.verdict !== v.trust_status) problems.push(where + ": the statements name a different verdict than the verifier gave");
      if (v.trust_status === "TRUSTED") trusted += 1; else notAccepted += 1;
    } else {
      if (file.result) problems.push(where + ": has a result and no ok flag");
      const code = file.error && file.error.error;
      if (code === "not_run") notRun += 1; else refused += 1;
    }
  });
  const sum = answer.summary;
  if (sum.total !== answer.files.length) problems.push("the summary counts " + sum.total + " files and the result holds " + answer.files.length);
  if (sum.trusted !== trusted || sum.not_accepted !== notAccepted || sum.refused !== refused || sum.not_run !== notRun) {
    problems.push("the summary counts do not match the per-file results");
  }
  if (answer.complete === true && notRun !== 0) problems.push("marked complete but some files were not run");
  return problems;
}

function renderBatch(answer) {
  const rows = batchRows(answer);
  const body = $("batch-rows");
  body.replaceChildren();
  for (const row of rows) {
    const tr = document.createElement("tr");
    tr.dataset.id = row.id;
    const name = document.createElement("td");
    name.textContent = row.name;
    const verdict = document.createElement("td");
    if (row.verdict !== null) { verdict.textContent = row.verdict; verdict.dataset.status = row.verdict; }
    else verdict.textContent = "No verdict";
    const detail = document.createElement("td");
    if (row.verdict !== null) {
      const parts = row.statements.map((s) => s.label + ": " + s.stateText);
      detail.textContent = parts.join(" · ");
    } else detail.textContent = row.message;
    tr.append(name, verdict, detail);
    body.append(tr);
  }
  const sum = answer.summary;
  $("batch-summary").textContent = sum.total + " file(s): " + sum.trusted + " with the verdict TRUSTED, " + sum.not_accepted +
    " with another verdict, " + sum.refused + " refused, " + sum.not_run + " not run." +
    (answer.complete === true ? "" : " The batch did not finish: files marked not run were not checked.");
  $("batch-note").textContent = answer.not_a_claim || "";
  show("batch-result", true);
}

async function verifyBatch() {
  const picked = Array.from($("batch-files").files || []);
  const status = await (await fetch("/api/status")).json();
  if (status.state === "unavailable") { unavailable(); return; }
  const plan = planBatch(picked, batchLimits(status));
  if (!plan.ok) { fail(plan.message); return; }
  $("batch-verify").disabled = true;
  show("batch-cancel", true);
  show("failure", false);
  show("batch-result", false);
  show("saved", false);
  lastBatch = null;
  batchAbort = new AbortController();
  try {
    // Read one file at a time into one list, then send once. The list is dropped as soon as the request is built.
    let entries = [];
    for (const file of picked) entries.push({ name: file.name, bytes: new Uint8Array(await file.arrayBuffer()) });
    const request = batchRequestBody(entries);
    entries = null;
    const response = await fetch("/api/verify-batch", {
      method: "POST", headers: { "Content-Type": "application/json" }, body: request, signal: batchAbort.signal,
    });
    const answer = JSON.parse(await response.text());
    if (answer.state === "unavailable") { unavailable(); return; }
    if (!response.ok || answer.schema !== BATCH_SCHEMA) {
      fail(answer.message || "The batch could not be checked, so there is no verdict for any file. Treat the reports as not accepted.");
      return;
    }
    const problems = validateBatch(answer);
    if (problems.length > 0) {
      fail("The portal's answer was not consistent, so it is not shown: " + problems[0] + ". Treat the reports as not accepted.");
      return;
    }
    lastBatch = answer;
    renderBatch(answer);
  } catch (error) {
    if (error && error.name === "AbortError") fail("The batch was cancelled. Files not yet checked have no verdict.");
    else fail("The batch could not be completed, so there is no verdict for any file. Treat the reports as not accepted.");
  } finally {
    batchAbort = null;
    show("batch-cancel", false);
    $("batch-verify").disabled = false;
  }
}

async function downloadBatch() {
  if (lastBatch === null) return;
  const status = await (await fetch("/api/status")).json();
  const result = { synthetic_demonstration: lastBatch.demonstration_label !== undefined };
  if (!savePermitted(status, result)) {
    if (status.state === "unavailable") unavailable();
    else fail("This portal cannot save a result right now. Contact your administrator.");
    return;
  }
  // Checked again at the moment of saving: a file that would contradict the verifier is never written.
  const problems = validateBatch(lastBatch);
  if (problems.length > 0) { fail("The batch result was not saved: " + problems[0] + "."); return; }
  const kind = result.synthetic_demonstration ? "demonstration-batch-result-" : "verification-batch-result-";
  const fileName = kind + String(lastBatch.batch_id).slice(0, 12) + ".json";
  const link = document.createElement("a");
  link.href = URL.createObjectURL(new Blob([JSON.stringify(lastBatch, null, 2) + "\n"], { type: "application/json" }));
  link.download = fileName;
  link.click();
  URL.revokeObjectURL(link.href);
  $("saved").textContent = "Saved to your downloads as " + fileName;
  show("saved", true);
}

async function start() {
  const body = await (await fetch("/api/status")).json();
  if (body.state === "unavailable") {
    unavailable();
    return;
  }
  $("claim").textContent = body.not_a_claim;
  // Which mode the portal is in, from the configuration it was started with. Nothing on this page can change it.
  $("trust-mode").textContent = body.trust_mode_text || "";
  $("trust-mode").className = body.trust_mode === "demonstration" ? "statement demo-banner" : "statement";
  ownReady = body.ready === true;
  // A demonstration trust list is never trust set up by an administrator: files are checked against it only as a
  // demonstration, and the upload screen says so before anything is chosen.
  const demonstrationOnly = body.state === "demonstration" && body.demonstration_checks === true;
  $("upload-demo-note").textContent = demonstrationOnly ? body.message : "";
  show("upload-demo-note", demonstrationOnly);
  ownReady = ownReady || demonstrationOnly;
  $("not-ready-message").textContent = ownReady ? "" : body.message;
  show("record-notice", body.replay_mode === "record");
  $("policy").textContent = (body.policy_text ? body.policy_text + " " : "") + body.engine.summary;
  listSamples(body.samples || []);
  $("choose-samples").disabled = (body.samples || []).length === 0;
  showView("welcome");
}

$("file").addEventListener("change", (event) => choose(event.target.files[0]));
$("verify").addEventListener("click", verifyChosen);
$("download").addEventListener("click", download);
$("batch-verify").addEventListener("click", verifyBatch);
$("batch-cancel").addEventListener("click", () => { if (batchAbort) batchAbort.abort(); });
$("batch-download").addEventListener("click", downloadBatch);
$("again").addEventListener("click", () => {
  $("file").value = "";
  choose(null);
  showView(lastView);
});
$("choose-samples").addEventListener("click", () => showView("samples"));
$("choose-own").addEventListener("click", () => showView("own"));
for (const back of document.querySelectorAll(".back")) {
  back.addEventListener("click", () => {
    choose(null);
    showView("welcome");
  });
}
const drop = $("drop");
drop.addEventListener("dragover", (event) => {
  event.preventDefault();
  drop.classList.add("over");
});
drop.addEventListener("dragleave", () => drop.classList.remove("over"));
drop.addEventListener("drop", (event) => {
  event.preventDefault();
  drop.classList.remove("over");
  choose(event.dataTransfer.files[0]);
});

start().catch(() => fail("This page could not reach the portal. Nothing can be verified."));
