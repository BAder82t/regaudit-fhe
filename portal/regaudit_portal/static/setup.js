"use strict";

// This page only reads. It asks the portal what is set up and shows the answer with textContent. It sends nothing, and it has no form.

const $ = (id) => document.getElementById(id);
const STATES = {
  ok: "Ready",
  missing: "Not set up",
  problem: "Needs attention",
  not_checked: "Not checked yet",
  demonstration: "Demonstration only, not trust",
};

function line(label, text) {
  const item = document.createElement("span");
  item.className = "fine";
  item.textContent = label + text;
  return item;
}

function statement(body) {
  if (body.own_reports.ready && body.trust_configured) return "Verification of your own reports is ready.";
  if (body.own_reports.ready) return "The portal can check your own reports, but a requirement below needs attention.";
  return body.own_reports.message;
}

function render(body) {
  $("folder").textContent = body.location_for_this_computer;
  $("file-name").textContent = body.config_file_name;
  $("own-reports").textContent = statement(body);
  const list = $("rows");
  list.replaceChildren();
  for (const row of body.rows) {
    const name = document.createElement("dt");
    name.textContent = row.title;
    const value = document.createElement("dd");
    const state = document.createElement("strong");
    state.textContent = STATES[row.state] || row.state;
    state.dataset.state = row.state;
    value.append(state, " ", row.detail);
    if (row.why) value.append(document.createElement("br"), line("Why it matters: ", row.why));
    if (row.next_step) value.append(document.createElement("br"), line("Next step: ", row.next_step));
    list.append(name, value);
  }
  $("status-message").textContent = "Configuration location: " + body.configuration_in_use;
  // How to type the commands on this computer: by their plain names, or by the full path of the programs in the application.
  $("cmd-intro").textContent = body.commands.intro;
  $("cmd-trust-add").textContent = body.commands.trust_add;
  $("cmd-check-config").textContent = body.commands.check_config;
  $("cmd-admin-describe").textContent = body.commands.admin_describe;
  $("cmd-admin-apply").textContent = body.commands.admin_apply;
}

async function start() {
  const response = await fetch("/api/setup");
  const body = await response.json();
  if (body.state === "unavailable") {
    $("status-message").textContent = "Verification is unavailable, so nothing can be shown here.";
    return;
  }
  render(body);
}

start().catch(() => {
  $("status-message").textContent = "This page could not reach the portal.";
});
