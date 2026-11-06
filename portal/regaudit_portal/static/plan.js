"use strict";

// Prepares a setup plan. It sends what is entered to the portal's stateless check, shows the answer with textContent,
// and offers the plan as a file to save. It stores nothing in the browser, and nothing here can apply a plan.

const $ = (id) => document.getElementById(id);
const MAX_ISSUERS = 10;
// Text that only private or secret key material carries. The portal checks this too; checking here first means such
// text is never sent at all. In the public key box any mention of PRIVATE or SECRET is enough.
const SECRET = /-----BEGIN[^\n-]*(PRIVATE|SECRET)|(PRIVATE|SECRET)\s+KEY\s*(BLOCK\s*)?-----|PuTTY-User-Key-File|Private-Lines\s*:|AGE-SECRET-KEY-|openssh-key-v1|b3BlbnNzaC1rZXktdjE/i;
const SECRET_IN_KEY_BOX = /PRIVATE|SECRET/i;
let prepared = null;

function element(tag, text) {
  const made = document.createElement(tag);
  if (text !== undefined) made.textContent = text;
  return made;
}

function field(labelText, control) {
  const id = "f" + Math.random().toString(36).slice(2);
  const wrap = element("p");
  wrap.className = "field";
  const label = element("label", labelText);
  label.htmlFor = id;
  control.id = id;
  control.autocomplete = "off";
  control.spellcheck = false;
  control.setAttribute("autocapitalize", "off");
  control.setAttribute("autocorrect", "off");
  wrap.append(label, control);
  return wrap;
}

function forget() {
  prepared = null;
  $("result").hidden = true;
  $("saved").textContent = "";
}

function renumber() {
  const sets = $("issuers").querySelectorAll("fieldset");
  sets.forEach((set, index) => {
    set.querySelector("legend").textContent = "Issuer " + (index + 1);
    set.querySelector("button").hidden = sets.length === 1;
  });
  $("add-issuer").disabled = sets.length >= MAX_ISSUERS;
}

function addIssuer() {
  const set = element("fieldset");
  set.className = "issuer";
  set.append(element("legend"));
  const name = element("input");
  name.type = "text";
  name.maxLength = 256;
  name.dataset.member = "issuer";
  const keyId = element("input");
  keyId.type = "text";
  keyId.maxLength = 128;
  keyId.dataset.member = "key_id";
  const key = element("textarea");
  key.rows = 4;
  key.dataset.member = "public_key";
  key.placeholder = "-----BEGIN PUBLIC KEY-----";
  const fingerprint = element("input");
  fingerprint.type = "text";
  fingerprint.maxLength = 200;
  fingerprint.dataset.member = "fingerprint";
  const remove = element("button", "Remove this issuer");
  remove.type = "button";
  remove.className = "quiet";
  remove.addEventListener("click", () => {
    set.remove();
    renumber();
    forget();
  });
  set.append(
    field("Issuer name, exactly as their reports give it", name),
    field("Key id", keyId),
    field("Their public key (PEM, starts with -----BEGIN PUBLIC KEY-----)", key),
    field("The fingerprint they gave you by another route (64 characters, 0-9 and a-f)", fingerprint),
    remove,
  );
  $("issuers").append(set);
  renumber();
}

function choice(name, value, title, lines, checked) {
  const label = element("label");
  label.className = "option";
  const input = element("input");
  input.type = "radio";
  input.name = name;
  input.value = value;
  input.checked = checked;
  const text = element("span");
  text.append(element("strong", title));
  for (const said of lines) text.append(" ", said);
  label.append(input, " ", text);
  return label;
}

function renderGuide(guide) {
  $("common").textContent = guide.common;
  for (const profile of guide.profiles) {
    const lines = [profile.summary, ...profile.does, ...profile.does_not];
    $("profiles").append(choice("profile", profile.name, profile.title + ".", lines, false));
  }
  for (const mode of guide.replay_modes) {
    $("replay-modes").append(choice("replay", mode.name, "", [mode.text], mode.name === "check"));
  }
  $("verifier-help").textContent = guide.verifier_id;
  $("max-age-help").textContent = guide.max_age;
}

function chosen(name) {
  const picked = document.querySelector('input[name="' + name + '"]:checked');
  return picked ? picked.value : null;
}

function collect() {
  const mode = chosen("mode");
  const request = { mode: mode, issuers: [] };
  if (mode === "first-setup") {
    const days = Number($("max-age").value);
    request.configuration = {
      profile: chosen("profile"),
      verifier_id: $("verifier-id").value,
      max_age_days: Number.isInteger(days) ? days : $("max-age").value,
      replay_mode: chosen("replay"),
    };
  }
  for (const set of $("issuers").querySelectorAll("fieldset")) {
    const issuer = {};
    for (const control of set.querySelectorAll("[data-member]")) issuer[control.dataset.member] = control.value;
    request.issuers.push(issuer);
  }
  return request;
}

function looksSecret(request) {
  const texts = [];
  const walk = (value) => {
    if (typeof value === "string") texts.push(value);
    else if (value && typeof value === "object") Object.values(value).forEach(walk);
  };
  walk(request);
  return texts.some((text) => SECRET.test(text)) || request.issuers.some((issuer) => SECRET_IN_KEY_BOX.test(issuer.public_key));
}

function typedFingerprints() {
  return Array.from($("issuers").querySelectorAll('[data-member="fingerprint"]'), (input) => input.value.trim());
}

function showFingerprints(rows) {
  const typed = typedFingerprints();
  const body = $("fingerprints");
  body.replaceChildren();
  for (const row of rows) {
    const line = element("tr");
    const who = element("td", row.number + ". " + row.issuer + " (key id " + row.key_id + ")");
    const mine = element("td");
    mine.append(element("code", typed[row.number - 1] || ""));
    const computed = element("td");
    computed.append(element("code", row.computed_fingerprint));
    const match = element("td", row.matches ? "Yes" : "No: does not match");
    line.append(who, mine, computed, match);
    body.append(line);
  }
}

function showWrites(body) {
  const writes = $("writes");
  writes.replaceChildren();
  for (const write of body.writes) {
    writes.append(element("p", write.file + ", readable and writable by this account only (" + write.mode + ")"));
    if (write.note) writes.append(element("p", write.note));
    writes.append(element("pre", write.text));
  }
  const summary = $("summary");
  summary.replaceChildren(...body.summary.map((text) => element("li", text)));
  const steps = $("next-steps");
  steps.replaceChildren(...body.next_steps.map((text) => element("li", text)));
}

async function check() {
  forget();
  const request = collect();
  if (looksSecret(request)) {
    $("message").textContent =
      "Something you entered looks like a private or secret key, so nothing was sent. Only the issuer's public key belongs in a plan.";
    return;
  }
  $("message").textContent = "Checking...";
  const response = await fetch("/api/setup/plan", {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(request),
  });
  const body = await response.json();
  if (body.state === "unavailable") {
    $("message").textContent = body.message;
    return;
  }
  if (body.issuers) {
    showFingerprints(body.issuers);
    $("result").hidden = false;
  }
  if (!body.ok) {
    $("written").hidden = true;
    $("message").textContent = (body.where ? body.where + ": " : "") + body.message;
    return;
  }
  prepared = body;
  $("written").hidden = false;
  showWrites(body);
  $("message").textContent = "The plan is ready to save. Nothing was written and nothing was kept by the portal.";
}

function save() {
  if (prepared === null) return;
  const link = element("a");
  link.href = URL.createObjectURL(new Blob([prepared.plan_text], { type: "application/json" }));
  link.download = prepared.file_name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  $("saved").textContent = "Saved to your downloads as " + prepared.file_name + ".";
}

function showMode() {
  $("settings").hidden = chosen("mode") !== "first-setup";
  forget();
}

async function start() {
  const response = await fetch("/api/setup");
  const body = await response.json();
  if (body.state === "unavailable") {
    $("unavailable").hidden = false;
    $("plan-form").hidden = true;
    return;
  }
  renderGuide(body.guide);
  addIssuer();
  for (const radio of document.querySelectorAll('input[name="mode"]')) radio.addEventListener("change", showMode);
  $("plan-form").addEventListener("input", forget);
  $("add-issuer").addEventListener("click", () => {
    addIssuer();
    forget();
  });
  $("check").addEventListener("click", () => {
    check().catch(() => {
      $("message").textContent = "This page could not reach the portal. Nothing was sent or kept.";
    });
  });
  $("save").addEventListener("click", save);
}

start().catch(() => {
  $("message").textContent = "This page could not reach the portal.";
});
