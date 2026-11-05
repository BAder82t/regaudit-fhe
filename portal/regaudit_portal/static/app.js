"use strict";

// Everything from the server is shown with textContent. The page shows the verdict it receives and never works one out.

const $ = (id) => document.getElementById(id);
const CHOOSE = "Drop a report file (.json) here, or click to choose one";
const LIMIT = 1048576;
let chosen = null;
let lastSaved = null;

function show(id, visible) {
  $(id).hidden = !visible;
}

// The engine is missing or failed its check: nothing can be verified or saved until the administrator fixes it.
function unavailable() {
  show("upload", false);
  show("result", false);
  show("failure", false);
  show("not-ready", false);
  show("record-notice", false);
  show("saved", false);
  show("unavailable", true);
  // Nothing that names the engine, the policy or a result may stay on screen once the engine has stopped passing.
  for (const id of ["policy", "claim", "engine-summary", "engine-scope", "check-key", "raw", "verdict", "result-file"]) {
    $(id).textContent = "";
  }
  chosen = null;
  lastSaved = null;
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
    render(body, chosen.name);
  } catch (error) {
    fail("The check could not be completed, so there is no verdict. Treat the report as not accepted.");
  } finally {
    $("verify").disabled = !chosen;
  }
}

async function download() {
  if (lastSaved === null) return;
  // No saved result is produced unless the engine passes its check at this moment.
  const status = await (await fetch("/api/status")).json();
  if (!status.ready) {
    if (status.state === "unavailable") unavailable();
    else fail("This portal cannot save a result right now. Contact your administrator.");
    return;
  }
  const stem = lastSaved.name.replace(/\.json$/i, "").replace(/[^A-Za-z0-9._-]+/g, "-").slice(0, 80) || "report";
  const fileName = "verification-result-" + stem + "-" + lastSaved.body.report_sha256.slice(0, 12) + ".json";
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
  if (!body.ready) {
    $("not-ready-message").textContent = body.message;
    show("not-ready", true);
    return;
  }
  show("upload", true);
  show("record-notice", body.replay_mode === "record");
  $("policy").textContent =
    body.policy_text + " " + body.engine.summary;
}

$("file").addEventListener("change", (event) => choose(event.target.files[0]));
$("verify").addEventListener("click", verifyChosen);
$("download").addEventListener("click", download);
$("again").addEventListener("click", () => {
  $("file").value = "";
  choose(null);
  $("drop").scrollIntoView({ behavior: "smooth", block: "nearest" });
});
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
