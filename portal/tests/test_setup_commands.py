"""The setup page names the commands the way they can be typed on this computer.

In a normal install they are on the search path under their plain names. Inside the macOS application they are programs in
``Contents/Resources/tools`` next to the bundled Python, run by their full path. Only the running interpreter's own place
decides which, and nothing is read from the environment.
"""

from __future__ import annotations

import ast
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
from helpers import client_for, fake_home, install_configuration, snapshot
from regaudit_portal.paths import bundled_command, default_config_folder, shell_path

PORTAL = Path(__file__).parents[1]
STATIC = PORTAL / "regaudit_portal" / "static"
NODE = shutil.which("node")
APP = "Evidence Verification Portal.app"
PLAIN_TRUST = (
    'regaudit-fhe trust add --store trust-store.json --key-id KEY_ID --issuer "ISSUER NAME" \\\n'
    "  --public-key issuer.pub --fingerprint FINGERPRINT"
)


def make_app(
    root: Path, *, wrappers: tuple[str, ...] = ("regaudit-fhe", "regaudit-portal")
) -> Path:
    """An application folder with the bundled Python and, in ``tools``, the named wrapper programs. Returns the Python."""
    resources = root / APP / "Contents" / "Resources"
    python = resources / "python" / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_text("")
    if wrappers is not None:
        (resources / "tools").mkdir()
        for name in wrappers:
            (resources / "tools" / name).write_text("#!/bin/sh\n")
    return python


def tools_of(python: Path) -> Path:
    return python.resolve().parents[2] / "tools"


def asked(client) -> dict:
    return client.get("/api/setup").json()["commands"]


@pytest.fixture
def home(tmp_path, monkeypatch) -> Path:
    return fake_home(tmp_path.resolve(), monkeypatch)


# ----------------------------------------------------------------------------- a normal install keeps the plain names


def test_with_no_tools_folder_the_commands_are_the_plain_names(tmp_path, home, monkeypatch, demo):
    python = tmp_path.resolve() / "venv" / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_text("")
    monkeypatch.setattr(sys, "executable", str(python))
    commands = asked(client_for(None))
    assert commands["in_application"] is False
    assert commands["trust_add"] == PLAIN_TRUST
    assert commands["check_config"] == "regaudit-portal check-config"
    assert "Terminal" not in commands["intro"] and "full path" not in commands["intro"]
    assert commands["intro"].startswith("Run this once for each issuer key, in the folder above")


def test_a_tools_folder_with_nothing_of_ours_in_it_changes_nothing(tmp_path, home, monkeypatch):
    python = make_app(tmp_path.resolve(), wrappers=())
    assert tools_of(python).is_dir()
    monkeypatch.setattr(sys, "executable", str(python))
    commands = asked(client_for(None))
    assert commands["in_application"] is False and commands["trust_add"] == PLAIN_TRUST
    assert commands["check_config"] == "regaudit-portal check-config"


def test_the_plain_answer_is_what_the_page_already_says_before_it_asks(home, monkeypatch, tmp_path):
    python = tmp_path.resolve() / "venv" / "bin" / "python3"
    python.parent.mkdir(parents=True)
    python.write_text("")
    monkeypatch.setattr(sys, "executable", str(python))
    html = (STATIC / "setup.html").read_text()
    commands = asked(client_for(None))
    assert f'<p id="cmd-intro">{commands["intro"]}</p>' in html
    assert f'<pre id="cmd-trust-add">{commands["trust_add"]}</pre>' in html
    assert f'<code id="cmd-check-config">{commands["check_config"]}</code>' in html


# ----------------------------------------------------------------------------- inside the application, by full path


def test_inside_the_application_the_commands_are_the_wrapper_programs_by_full_path(
    tmp_path, home, monkeypatch
):
    python = make_app(tmp_path.resolve() / "Applications Folder")
    monkeypatch.setattr(sys, "executable", str(python))
    tools = tools_of(python)
    commands = asked(client_for(None))
    assert commands["in_application"] is True
    quoted_trust = "'" + str(tools / "regaudit-fhe") + "'"
    quoted_check = "'" + str(tools / "regaudit-portal") + "'"
    assert commands["trust_add"] == (
        f"{quoted_trust} trust add --store trust-store.json --key-id KEY_ID "
        '--issuer "ISSUER NAME" \\\n  --public-key issuer.pub --fingerprint FINGERPRINT'
    )
    assert commands["check_config"] == f"{quoted_check} check-config"
    assert "Terminal" in commands["intro"] and "full path" in commands["intro"]
    assert "Run this once for each issuer key" not in commands["intro"]


def test_a_path_without_spaces_needs_no_quotes(tmp_path, home, monkeypatch):
    root = tmp_path.resolve() / "plain"
    resources = root / "App" / "Contents" / "Resources"
    (resources / "python" / "bin").mkdir(parents=True)
    (resources / "python" / "bin" / "python3").write_text("")
    (resources / "tools").mkdir()
    for name in ("regaudit-fhe", "regaudit-portal"):
        (resources / "tools" / name).write_text("")
    monkeypatch.setattr(sys, "executable", str(resources / "python" / "bin" / "python3"))
    commands = asked(client_for(None))
    assert commands["trust_add"].startswith(f"{resources / 'tools' / 'regaudit-fhe'} trust add ")
    assert commands["check_config"] == f"{resources / 'tools' / 'regaudit-portal'} check-config"


def test_an_application_under_the_home_folder_is_shown_with_a_tilde_and_the_rest_quoted(
    home, monkeypatch
):
    python = make_app(home / "Applications")
    monkeypatch.setattr(sys, "executable", str(python))
    commands = asked(client_for(None))
    inside = f"Applications/{APP}/Contents/Resources/tools"
    assert commands["trust_add"].startswith(f"~/'{inside}/regaudit-fhe' trust add ")
    assert commands["check_config"] == f"~/'{inside}/regaudit-portal' check-config"
    assert str(home) not in json.dumps(commands)


def test_the_wrappers_are_found_through_a_link_to_the_bundled_python(tmp_path, home, monkeypatch):
    python = make_app(tmp_path.resolve())
    real = python.with_name("python3.12")
    python.rename(real)
    python.symlink_to(real.name)
    monkeypatch.setattr(sys, "executable", str(python))
    assert asked(client_for(None))["in_application"] is True


def test_one_wrapper_missing_shows_the_plain_name_for_that_command_only(
    tmp_path, home, monkeypatch
):
    python = make_app(tmp_path.resolve(), wrappers=("regaudit-portal",))
    monkeypatch.setattr(sys, "executable", str(python))
    commands = asked(client_for(None))
    assert commands["in_application"] is True
    assert commands["trust_add"].startswith("regaudit-fhe trust add ")
    assert commands["check_config"].endswith("regaudit-portal' check-config")


def test_the_page_script_puts_the_answer_into_the_page():
    script = (STATIC / "setup.js").read_text()
    html = (STATIC / "setup.html").read_text()
    for field, element in (
        ("intro", "cmd-intro"),
        ("trust_add", "cmd-trust-add"),
        ("check_config", "cmd-check-config"),
    ):
        assert f'$("{element}").textContent = body.commands.{field};' in script
        assert f'id="{element}"' in html


# ----------------------------------------------------------------------------- what a shell makes of the paths shown


@pytest.mark.skipif(not Path("/bin/sh").exists(), reason="no shell")
@pytest.mark.parametrize(
    "name", ["Evidence Verification Portal.app", "a b  c", "it's here", "$HOME x", "plain"]
)
def test_the_path_shown_is_what_a_shell_reads_back_as_that_path(tmp_path, home, name):
    for place in (tmp_path.resolve() / name / "tools" / "x", home / name / "tools" / "x"):
        shown = shell_path(place)
        done = subprocess.run(  # noqa: S603 - the shell is what reads the path back
            ["/bin/sh", "-c", f"printf %s {shown}"],
            capture_output=True,
            text=True,
            env={"HOME": str(home), "PATH": "/usr/bin:/bin"},
            timeout=20,
            check=True,
        )
        assert done.stdout == str(place), shown


def test_a_place_under_the_home_folder_keeps_its_tilde_outside_the_quotes(home):
    assert shell_path(home / "a b" / "c") == "~/'a b/c'"
    assert shell_path(home / "ab" / "c") == "~/ab/c"
    assert shell_path(Path("/Applications") / "A B.app" / "x") == "'/Applications/A B.app/x'"


# ----------------------------------------------------------------------------- nothing else is shown, nothing is created


def test_the_setup_answer_shows_no_place_but_the_two_wrapper_paths(
    tmp_path, home, monkeypatch, demo
):
    root = tmp_path.resolve() / "elsewhere"
    python = make_app(root)
    monkeypatch.setattr(sys, "executable", str(python))
    client = client_for(install_configuration(demo, default_config_folder()))
    text = client.get("/api/setup").text
    answer = json.loads(text)
    own = {
        shell_path(tools_of(python) / "regaudit-fhe"),
        shell_path(tools_of(python) / "regaudit-portal"),
    }
    assert all(
        path in answer["commands"]["trust_add"] + answer["commands"]["check_config"] for path in own
    )
    rest = json.dumps(answer, ensure_ascii=False)
    for path in own:
        rest = rest.replace(json.dumps(path)[1:-1], "")
    for other in (str(root), str(tmp_path), str(python), "python/bin", "Contents", str(home)):
        assert other not in rest, other
    assert str(python.resolve()) not in text


def test_looking_at_the_setup_page_inside_the_application_creates_and_changes_nothing(
    tmp_path, home, monkeypatch
):
    python = make_app(home / "Applications")
    monkeypatch.setattr(sys, "executable", str(python))
    before = snapshot(tmp_path.resolve())
    client = client_for(None)
    for path in ("/setup", "/api/setup", "/api/status"):
        assert client.get(path).status_code == 200
    assert snapshot(tmp_path.resolve()) == before
    assert not default_config_folder().exists()


def test_nothing_is_read_from_the_environment_to_decide(tmp_path, home, monkeypatch):
    python = make_app(tmp_path.resolve())
    monkeypatch.setattr(sys, "executable", str(python))
    for name in ("REGAUDIT_APP", "REGAUDIT_PORTAL_APP", "REGAUDIT_TOOLS", "TOOLS", "RESOURCEPATH"):
        monkeypatch.setenv(name, str(tmp_path / "nowhere"))
    assert bundled_command("regaudit-fhe") == tools_of(python) / "regaudit-fhe"
    plain = tmp_path.resolve() / "venv" / "bin" / "python3"
    plain.parent.mkdir(parents=True)
    plain.write_text("")
    monkeypatch.setattr(sys, "executable", str(plain))
    for name in ("REGAUDIT_APP", "REGAUDIT_PORTAL_APP", "REGAUDIT_TOOLS", "TOOLS", "RESOURCEPATH"):
        monkeypatch.setenv(name, str(tools_of(python)))
    assert bundled_command("regaudit-fhe") is None
    for name in ("paths.py", "setup.py"):
        tree = ast.parse((PORTAL / "regaudit_portal" / name).read_text())
        used = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)} | {
            n.id for n in ast.walk(tree) if isinstance(n, ast.Name)
        }
        assert not used & {"environ", "environb", "getenv", "getenvb"}, name


def test_an_interpreter_with_no_place_of_its_own_gives_no_wrapper(monkeypatch):
    monkeypatch.setattr(sys, "executable", "")
    assert bundled_command("regaudit-fhe") is None
    monkeypatch.setattr(sys, "executable", "/python3")
    assert bundled_command("regaudit-fhe") is None


# ----------------------------------------------------------------------------- the page, as a browser would fill it


HARNESS = r"""
const fs = require("fs");
const input = JSON.parse(fs.readFileSync(0, "utf8"));
const elements = {};
const element = (id) => elements[id] || (elements[id] = { textContent: "", children: [],
  replaceChildren() { this.children = []; }, append(...items) { this.children.push(...items); }, dataset: {} });
const document = { getElementById: element, createElement: () => element("created-" + Math.random()) };
const fetch = async () => ({ json: async () => input.answer });
const run = new Function("document", "fetch", input.source);
run(document, fetch);
setTimeout(() => {
  const text = {};
  for (const id of ["cmd-intro", "cmd-trust-add", "cmd-check-config", "status-message"]) text[id] = element(id).textContent;
  process.stdout.write(JSON.stringify(text));
}, 50);
"""


@pytest.mark.skipif(NODE is None, reason="Node is not installed")
@pytest.mark.parametrize("inside", [False, True])
def test_the_page_shows_the_commands_the_portal_answers_with(tmp_path, home, monkeypatch, inside):
    python = make_app(tmp_path.resolve()) if inside else tmp_path.resolve() / "bin" / "python3"
    if not inside:
        python.parent.mkdir(parents=True)
        python.write_text("")
    monkeypatch.setattr(sys, "executable", str(python))
    answer = client_for(None).get("/api/setup").json()
    done = subprocess.run(  # noqa: S603 - fixed argv, no shell
        [NODE, "-e", HARNESS],
        input=json.dumps({"source": (STATIC / "setup.js").read_text(), "answer": answer}),
        capture_output=True,
        text=True,
        timeout=60,
        check=True,
    )
    shown = json.loads(done.stdout)
    assert shown["cmd-intro"] == answer["commands"]["intro"]
    assert shown["cmd-trust-add"] == answer["commands"]["trust_add"]
    assert shown["cmd-check-config"] == answer["commands"]["check_config"]
    assert ("Terminal" in shown["cmd-intro"]) is inside
    assert shown["status-message"].startswith("Configuration location: ")


def test_the_page_still_says_that_guided_trust_creation_in_the_browser_is_not_built():
    html = (STATIC / "setup.html").read_text()
    assert "For now, making the trust list needs these commands." in html
    assert "Creating it in the browser would be a separate change" in html
    assert "This page does not do it." in html
    readme = (PORTAL / "README.md").read_text()
    assert "Guided creation of the trust list in the browser is not built." in readme
