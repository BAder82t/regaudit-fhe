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
  show("failure", false);
  show("record-notice", false);
  show("saved", false);
  show("unavailable", true);
  // Nothing that names the engine, the policy or a result may stay on screen once the engine has stopped passing.
  for (const id of ["policy", "claim", "engine-summary", "engine-scope", "check-key", "raw", "verdict", "result-file", "demo-banner"]) {
    $(id).textContent = "";
  }
  $("sample-list").replaceChildren();
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
  $("demo-banner").textContent = demonstration ? body.demonstration.notice : "";
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

  $("raw").textContent = d.technical_details;
  show("failure", false);
  show("result", true);
  $("result").scrollIntoView({ behavior: "smooth", block: "nearest" });
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

async function start() {
  const body = await (await fetch("/api/status")).json();
  if (body.state === "unavailable") {
    unavailable();
    return;
  }
  $("claim").textContent = body.not_a_claim;
  ownReady = body.ready === true;
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
