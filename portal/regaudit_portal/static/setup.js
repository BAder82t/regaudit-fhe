"use strict";

// This page only reads. It asks the portal what is set up and shows the answer with textContent. It sends nothing, and it has no form.

const $ = (id) => document.getElementById(id);
const STATES = { ok: "Ready", missing: "Not set up", problem: "Needs attention", not_checked: "Not checked yet" };

function render(body) {
  $("folder").textContent = body.location_for_this_computer;
  $("file-name").textContent = body.config_file_name;
  $("own-reports").textContent = body.own_reports.ready
    ? "Verification of your own reports is ready."
    : body.own_reports.message;
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
    list.append(name, value);
  }
  $("status-message").textContent = "Configuration location: " + body.configuration_in_use;
  // How to type the commands on this computer: by their plain names, or by the full path of the programs in the application.
  $("cmd-intro").textContent = body.commands.intro;
  $("cmd-trust-add").textContent = body.commands.trust_add;
  $("cmd-check-config").textContent = body.commands.check_config;
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
