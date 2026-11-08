"use strict";

// Prepares a setup plan. It sends what is entered to the portal's stateless check, shows the answer with textContent,
// and offers the plan as a file to save. It stores nothing in the browser, and nothing here can apply a plan.

const $ = (id) => document.getElementById(id);
const MAX_ISSUERS = 10;
// Text that only private or secret key material carries. The portal checks this too; checking here first means such
// text is never sent at all, including the bare body of an Ed25519 private key (its fixed start, MC4CAQAw...). In the
// public key box any mention of PRIVATE or SECRET is enough.
const SECRET = /-----BEGIN[^\n-]*(PRIVATE|SECRET)|(PRIVATE|SECRET)\s+KEY\s*(BLOCK\s*)?-----|PuTTY-User-Key-File|Private-Lines\s*:|AGE-SECRET-KEY-|openssh-key-v1|b3BlbnNzaC1rZXktdjE|MC4CAQAwBQYDK2VwBCIEI/i;
const SECRET_IN_KEY_BOX = /PRIVATE|SECRET/i;
// Only what saving the plan needs: its text and its file name. Nothing else from a check is kept.
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
  $("writes").replaceChildren();
  $("saved").textContent = "";
}

// After every check, whatever its outcome, the pasted public keys are taken out of their boxes, and so is any value
// that looked like a private or secret key, wherever it was typed. Paste a key again to check another plan.
function clearKeyMaterial() {
  const controls = [$("verifier-id"), ...$("issuers").querySelectorAll("[data-member]")];
  for (const control of controls) {
    if (control.dataset.member === "public_key" || SECRET.test(control.value)) control.value = "";
  }
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

// Only whether each typed fingerprint matches its key. The portal never sends the fingerprint it computes, because
// that is the value to check with the issuer, and this page never works one out.
function showFingerprints(rows) {
  const body = $("fingerprints");
  body.replaceChildren();
  for (const row of rows) {
    const line = element("tr");
    const who = element("td", row.number + ". " + row.issuer + " (key id " + row.key_id + ")");
    const match = element("td", row.matches ? "Yes" : "No: it does not match this key");
    line.append(who, match);
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

const KEYS_CLEARED = " The public keys you pasted were cleared from the page.";
const PASTE_AGAIN = " The public keys you pasted were cleared from the page, as after every check: paste them again.";
const MISMATCH_NEXT =
  " The public key box was emptied, as after every check: paste the public key again, then type the fingerprint the " +
  "issuer gave you and press Check the plan.";

function issuerControl(number, member) {
  const set = $("issuers").querySelectorAll("fieldset")[number - 1];
  return set ? set.querySelector('[data-member="' + member + '"]') : null;
}

// Everything that is missing or out of range, not only the first, in plain words, each with the box it is about. It is
// checked here before anything is sent, so that one press lists it all; the portal checks everything again.
function missing(request) {
  const found = [];
  const settings = request.configuration;
  if (settings) {
    if (!settings.profile) found.push(["Choose a profile.", document.querySelector('input[name="profile"]')]);
    if (!String(settings.verifier_id).trim()) found.push(["Type your verifier id.", $("verifier-id")]);
    const days = settings.max_age_days;
    if (!(Number.isInteger(days) && days >= 1 && days <= 3650)) {
      found.push(["Type the maximum report age as a whole number of days, from 1 to 3650.", $("max-age")]);
    }
    if (!settings.replay_mode) found.push(["Choose a replay mode.", document.querySelector('input[name="replay"]')]);
  }
  const boxes = [
    ["issuer", "type the issuer's name"],
    ["key_id", "type the key id"],
    ["public_key", "paste the issuer's public key"],
    ["fingerprint", "type the fingerprint the issuer gave you"],
  ];
  request.issuers.forEach((issuer, index) => {
    for (const [member, words] of boxes) {
      if (!String(issuer[member] || "").trim()) {
        found.push(["Issuer " + (index + 1) + ": " + words + ".", issuerControl(index + 1, member)]);
      }
    }
  });
  return found;
}

// Where the portal says a problem is, in plain words, and the box it is about. "configuration" adds nothing to a
// message that already names the setting, so it is left out.
const MEMBERS = { name: "issuer", "key id": "key_id", "public key": "public_key", fingerprint: "fingerprint" };
function place(where, message) {
  const issuer = /^issuer (\d+)(?:, (name|key id|public key|fingerprint))?$/.exec(where || "");
  if (issuer) {
    const label = "Issuer " + issuer[1] + (issuer[2] ? ", " + issuer[2] : "") + ": ";
    return [label, issuerControl(Number(issuer[1]), MEMBERS[issuer[2] || "name"])];
  }
  if (/verifier id/i.test(message)) return ["", $("verifier-id")];
  if (/maximum report age/i.test(message)) return ["", $("max-age")];
  if (/profile/i.test(message)) return ["", document.querySelector('input[name="profile"]')];
  if (/replay mode/i.test(message)) return ["", document.querySelector('input[name="replay"]')];
  return ["", null];
}

// The message, the list of problems that have words of their own, a mark on each box concerned, and the focus on the
// first of them.
function showProblems(lead, problems) {
  $("message").textContent = lead;
  const listed = problems.filter(([text]) => text);
  $("problems").replaceChildren(...listed.map(([text]) => element("li", text)));
  $("problems").hidden = listed.length === 0;
  for (const [, control] of problems) if (control) control.setAttribute("aria-invalid", "true");
  const first = problems.find(([, control]) => control);
  if (first) first[1].focus();
}

function clearProblems() {
  $("problems").replaceChildren();
  $("problems").hidden = true;
  for (const control of $("plan-form").querySelectorAll("[aria-invalid]")) control.removeAttribute("aria-invalid");
}

async function check() {
  forget();
  clearProblems();
  let request = collect();
  const secret = looksSecret(request);
  const pasted = request.issuers.some((issuer) => String(issuer.public_key || "").trim() !== "");
  clearKeyMaterial(); // from here the keys are only in this one request, which is dropped below
  if (secret) {
    request = null;
    $("message").textContent =
      "Something you entered looks like a private or secret key, so nothing was sent and it was cleared from the page." +
      KEYS_CLEARED +
      " Only the issuer's public key belongs in a plan.";
    return;
  }
  const problems = missing(request);
  if (problems.length) {
    request = null;
    showProblems(
      "Nothing was sent. Fill in what is missing, then press Check the plan again." + (pasted ? PASTE_AGAIN : ""),
      problems,
    );
    return;
  }
  $("message").textContent = "Checking...";
  let body;
  try {
    const response = await fetch("/api/setup/plan", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify(request),
    });
    request = null;
    body = await response.json();
  } finally {
    request = null;
  }
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
    if (body.error === "fingerprint_mismatch") {
      // Only whether each fingerprint matched is known here. The key box of the first that did not is emptied, as
      // after every check, so the focus goes there to paste the key again.
      const wrong = (body.issuers || []).filter((row) => !row.matches);
      showProblems(
        body.message + MISMATCH_NEXT,
        wrong.map((row) => ["", issuerControl(row.number, "public_key")]),
      );
      for (const row of wrong) {
        const typed = issuerControl(row.number, "fingerprint");
        if (typed) typed.setAttribute("aria-invalid", "true");
      }
      return;
    }
    const [label, control] = place(body.where, body.message || "");
    showProblems(label + body.message + (pasted ? PASTE_AGAIN : ""), control ? [["", control]] : []);
    return;
  }
  prepared = { plan_text: body.plan_text, file_name: body.file_name };
  $("written").hidden = false;
  $("save").hidden = false;
  showWrites(body);
  $("message").textContent =
    "The plan is ready to save. Nothing was written and nothing was kept by the portal." + KEYS_CLEARED;
}

function save() {
  if (prepared === null) return;
  const text = prepared.plan_text;
  const name = prepared.file_name;
  prepared = null; // saved once: the page keeps no copy of the plan, or of the keys in it
  const link = element("a");
  link.href = URL.createObjectURL(new Blob([text], { type: "application/json" }));
  link.download = name;
  document.body.append(link);
  link.click();
  link.remove();
  setTimeout(() => URL.revokeObjectURL(link.href), 1000);
  $("writes").replaceChildren();
  $("save").hidden = true;
  $("saved").textContent = "Saved to your downloads as " + name + ". The plan was cleared from this page.";
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
