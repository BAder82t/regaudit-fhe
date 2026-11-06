"""The look of the pages: nothing is fetched from outside, the fonts are served from the package, and the colours read well.

The design follows the VaultBytes website. It is a change of appearance only, so what these tests pin is what could go
wrong around it: a remote font or script creeping in, a file that should not be served being served, a colour pair that is
too faint to read, and a page that loses its landmarks, its skip link or its keyboard focus.
"""

from __future__ import annotations

import hashlib
import importlib.metadata
import re
from pathlib import Path

import pytest
import regaudit_portal.app as portal_app
import regaudit_portal.fallback as fallback_module
import tomllib

PORTAL = Path(__file__).parents[1]
STATIC = PORTAL / "regaudit_portal" / "static"
FONTS = STATIC / "fonts"
FONT_NAMES = (
    "inter-latin-wght-normal.woff2",
    "space-grotesk-latin-wght-normal.woff2",
    "jetbrains-mono-latin-wght-normal.woff2",
)
LICENCES = ("inter-OFL.txt", "space-grotesk-OFL.txt", "jetbrains-mono-OFL.txt")
PAGES = {"index.html": "/", "setup.html": "/setup", "security.html": "/security"}
LOCAL_LINKS = {"/", "/setup", "/security", "/static/app.css", "/static/app.js", "/static/setup.js"}
MARK = "/static/vaultbytes-mark.svg"


def written(*names: str) -> dict[str, str]:
    return {name: (STATIC / name).read_text() for name in names}


def pages() -> dict[str, str]:
    return written(*PAGES)


def assets() -> dict[str, str]:
    """Every text file the pages are made of."""
    return written(*PAGES, "app.css", "app.js", "setup.js", "vaultbytes-mark.svg")


# ----------------------------------------------------------------------------- nothing is fetched from outside


def test_nothing_the_pages_are_made_of_names_another_computer():
    for name, text in assets().items():
        # A comment's // is followed by a space, and a link to another computer has its name straight after the //.
        found = re.findall(r"(?:https?:)?//[A-Za-z0-9][^\s\"')>]*", text)
        if name.endswith(".svg"):
            found = [
                f for f in found if f != "http://www.w3.org/2000/svg"
            ]  # the namespace, not a link
        assert not found, (name, found)
    for name, text in assets().items():
        for forbidden in (
            "@import",
            "googleapis",
            "gstatic",
            "cdn.",
            "unpkg",
            "jsdelivr",
            "<iframe",
            "<object",
            "<embed",
            "<base",
            "data:",
            "ftp:",
        ):
            assert forbidden not in text.lower(), (name, forbidden)


def test_the_only_things_a_page_loads_are_its_own_files():
    for name, text in pages().items():
        loaded = set(re.findall(r'(?:src|href)="([^"]+)"', text))
        assert loaded <= LOCAL_LINKS | {MARK, "#main"}, (name, loaded - LOCAL_LINKS)
        for tag in re.findall(r"<link [^>]*>", text):
            assert 'href="/static/' in tag, (name, tag)
        for tag in re.findall(r"<script [^>]*>", text):
            assert re.search(r'src="/static/[a-z]+\.js"', tag), (name, tag)


def test_every_font_the_style_asks_for_is_a_bundled_file_and_every_bundled_font_is_used():
    css = (STATIC / "app.css").read_text()
    asked = re.findall(r"url\(([^)]*)\)", css)
    assert sorted(asked) == sorted(f'"/static/fonts/{name}"' for name in FONT_NAMES)
    assert css.count("@font-face") == 3 and css.count("font-display: swap") == 3
    for name in FONT_NAMES:
        assert (FONTS / name).read_bytes()[:4] == b"wOF2", name


def test_the_style_names_the_site_tokens_and_the_three_typefaces():
    css = (STATIC / "app.css").read_text()
    for token in (
        "--color-bg-primary",
        "--color-bg-secondary",
        "--color-text-primary",
        "--color-text-dim",
        "--color-accent",
        "--color-highlight",
        "--color-border",
        "--color-glow",
        "--color-blue-light",
        "--color-blue-medium",
        "--color-cyan",
        "--color-cyan-light",
        "--color-gray",
        "--color-gray-light",
        "--color-success",
        "--color-warning",
        "--font-primary",
        "--font-heading",
        "--font-mono",
        "--spacing-xs",
        "--spacing-xl",
        "--transition-fast",
        "--transition-medium",
        "--container-max-width: 1160px",
    ):
        assert token in css, token
    for family in ('"Inter"', '"Space Grotesk"', '"JetBrains Mono"'):
        assert f"font-family: {family}" in css


# ----------------------------------------------------------------------------- the fonts and the mark are served, and only those


def test_each_font_is_served_as_woff2_under_the_strict_policy(client):
    for name in FONT_NAMES:
        got = client.get(f"/static/fonts/{name}")
        assert got.status_code == 200 and got.headers["content-type"] == "font/woff2", name
        assert got.content == (FONTS / name).read_bytes() and got.content[:4] == b"wOF2"
        assert got.headers["x-content-type-options"] == "nosniff"
        assert got.headers["cache-control"] == "no-store"
        policy = got.headers["content-security-policy"]
        assert "font-src 'self'" in policy and "default-src 'none'" in policy
        head = client.head(f"/static/fonts/{name}")
        assert head.status_code == 200 and head.content == b""
        for header in ("content-type", "content-security-policy", "content-length"):
            assert head.headers[header] == got.headers[header], (name, header)


def test_the_mark_is_served_as_an_svg_image(client):
    got = client.get(MARK)
    assert got.status_code == 200 and got.headers["content-type"] == "image/svg+xml"
    assert got.content == (STATIC / "vaultbytes-mark.svg").read_bytes()
    assert "img-src 'self'" in got.headers["content-security-policy"]
    assert b"<script" not in got.content and b"href" not in got.content


def test_the_content_policy_allows_fonts_from_this_portal_and_nothing_else_from_anywhere(client):
    policy = client.get("/").headers["content-security-policy"]
    directives = dict(part.strip().split(" ", 1) for part in policy.split(";") if part.strip())
    assert directives["font-src"] == "'self'"
    assert directives["default-src"] == "'none'"
    for name, value in directives.items():
        assert value in ("'self'", "'none'"), (name, value)
    for loose in ("*", "http", "data:", "blob:", "unsafe"):
        assert loose not in policy, loose


@pytest.mark.parametrize(
    "path",
    [
        "/static/fonts/nope.woff2",
        "/static/fonts/FONTS.md",
        "/static/fonts/inter-OFL.txt",
        "/static/fonts/",
        "/static/fonts",
        "/static/fonts/Inter-latin-wght-normal.woff2",
        "/static/fonts/..%2Fapp.js",
        "/static/fonts/%2e%2e%2fapp.py",
        "/static/fonts/..%2F..%2Fconfig.py",
        "/static/fonts/%2e%2e/app.js",
        "/static/fonts/a/b.woff2",
        "/static/fonts/inter-latin-wght-normal.woff2%00",
        "/static/fonts/inter-latin-wght-normal.woff2;x",
        "/static/..%2Ffonts/inter-latin-wght-normal.woff2",
        "/static/inter-latin-wght-normal.woff2",
        "/static/fonts/vaultbytes-mark.svg",
    ],
)
def test_nothing_but_the_three_fonts_can_be_read_from_the_fonts_folder(client, path):
    assert client.get(path).status_code == 404
    assert client.head(path).status_code == 404


def test_the_list_of_fonts_in_the_code_is_the_fonts_in_the_folder():
    assert set(portal_app._FONT_FILES) == set(FONT_NAMES)
    assert {p.name for p in FONTS.glob("*.woff2")} == set(FONT_NAMES)
    assert set(portal_app._STATIC_FILES) == {
        "app.js",
        "app.css",
        "setup.js",
        "vaultbytes-mark.svg",
    }
    for place in (
        *portal_app._FONT_FILES.values(),
        *(p for p, _ in portal_app._STATIC_FILES.values()),
    ):
        assert place.is_file(), place


# ----------------------------------------------------------------------------- the fonts come with their licence


def test_each_font_has_its_licence_text_and_the_note_that_records_where_it_came_from():
    note = (FONTS / "FONTS.md").read_text()
    for name, licence in zip(FONT_NAMES, LICENCES, strict=True):
        text = (FONTS / licence).read_text()
        assert "SIL OPEN FONT LICENSE Version 1.1" in text and "Copyright" in text, licence
        for file in (name, licence):
            digest = hashlib.sha256((FONTS / file).read_bytes()).hexdigest()
            assert digest != hashlib.sha256(b"").hexdigest()
            assert f"`{digest}`" in note, file
            assert f"`{file}`" in note, file
    assert note.count("5.3.0") >= 6 and "SIL Open Font License, Version 1.1" in note
    assert "@fontsource-variable/inter" in note and "shasum -a 256 -c" in note


def test_the_fonts_and_their_licences_are_in_the_package_data():
    config = tomllib.loads((PORTAL / "pyproject.toml").read_text())
    patterns = config["tool"]["setuptools"]["package-data"]["regaudit_portal"]
    assert "static/fonts/*" in patterns and "static/*" in patterns
    for pattern in patterns:
        assert list((PORTAL / "regaudit_portal").glob(pattern)), pattern


def test_an_installed_copy_holds_the_fonts_the_licences_and_the_mark():
    try:
        installed = importlib.metadata.distribution("regaudit-portal")
    except importlib.metadata.PackageNotFoundError:
        pytest.skip("the portal is not installed here")
    if (
        Path(installed.locate_file("regaudit_portal")).resolve()
        != Path(portal_app.__file__).parent.resolve()
    ):
        pytest.skip("the portal under test is not the installed copy")
    listed = installed.files or []
    held = {str(p) for p in listed if str(p).startswith("regaudit_portal/")}
    if not held:
        pytest.skip("an editable install lists no files")
    for name in (*FONT_NAMES, *LICENCES, "FONTS.md"):
        assert f"regaudit_portal/static/fonts/{name}" in held, name
    assert "regaudit_portal/static/vaultbytes-mark.svg" in held


# ----------------------------------------------------------------------------- landmarks, skip link, focus and size


@pytest.mark.parametrize("name", PAGES)
def test_each_page_has_its_landmarks_a_skip_link_and_one_main_heading(name):
    text = pages()[name]
    assert text.startswith("<!doctype html>") and '<html lang="en">' in text
    assert 'name="viewport" content="width=device-width, initial-scale=1"' in text
    assert '<a class="skip-link" href="#main">' in text
    assert text.index('class="skip-link"') < text.index("<header")
    assert '<main id="main">' in text and text.count("<main") == 1
    assert text.count("<h1>") == 1 and "<h1>Evidence Verification Portal</h1>" in text
    assert '<nav aria-label="Portal">' in text and "<footer" in text
    assert f'rel="icon" type="image/svg+xml" href="{MARK}"' in text
    assert text.count('aria-current="page"') == 1
    assert f'<a href="{PAGES[name]}" aria-current="page">' in text
    assert '<img class="logo-icon" src="/static/vaultbytes-mark.svg" alt="" ' in text
    assert "&copy; 2026 VaultBytes Innovations Ltd." in text
    assert 'class="title-underline"' in text


def test_the_style_keeps_keyboard_focus_visible_and_respects_reduced_motion():
    css = (STATIC / "app.css").read_text()
    assert ":focus-visible" in css and "outline: 3px solid var(--color-accent)" in css
    assert "@media (prefers-reduced-motion: reduce)" in css and "transition: none !important" in css
    assert not re.search(r"outline:\s*(none|0)\b", css)
    assert "@media (max-width: 600px)" in css
    for selector in ("button {", ".nav-menu a {", ".logo {", "summary {"):
        block = css[css.index(selector) : css.index("}", css.index(selector))]
        assert "min-height: 44px" in block, selector


def test_the_verdict_is_told_by_its_words_and_a_shape_and_not_by_colour_alone():
    css = (STATIC / "app.css").read_text()
    script = (STATIC / "app.js").read_text()
    assert "verdict.dataset.status = v.trust_status;" in script
    assert "verdict.textContent = v.trust_status;" in script
    for rule in (
        ".verdict::before {",
        '.verdict[data-status="TRUSTED"]::before',
        '.verdict[data-status="SELF_SIGNED_ONLY"]::before',
    ):
        assert rule in css, rule
    # Three different shapes: a crossed square (the default), a filled circle and a triangle.
    assert (
        'content: "\\00d7"' in css and "border-radius: 50%" in css and "clip-path: polygon(" in css
    )
    for state in ("ok", "problem", "missing", "not_checked"):
        assert f'dd strong[data-state="{state}"]' in css, state
    assert css.count("DEMONSTRATION") == 1 and "border: 2px dashed var(--color-demo-text)" in css
    assert '$("result").classList.toggle("demonstration", demonstration);' in script


# ----------------------------------------------------------------------------- the colours read well


def _channel(value: int) -> float:
    unit = value / 255
    return unit / 12.92 if unit <= 0.03928 else ((unit + 0.055) / 1.055) ** 2.4


def luminance(rgb: tuple[int, int, int]) -> float:
    red, green, blue = (_channel(v) for v in rgb)
    return 0.2126 * red + 0.7152 * green + 0.0722 * blue


def ratio(first: tuple[int, int, int], second: tuple[int, int, int]) -> float:
    high, low = sorted((luminance(first), luminance(second)), reverse=True)
    return (high + 0.05) / (low + 0.05)


def rgb_of(text: str) -> tuple[int, int, int]:
    text = text.strip().lower()
    if match := re.fullmatch(r"#([0-9a-f]{3}|[0-9a-f]{6})", text):
        digits = match.group(1)
        if len(digits) == 3:
            digits = "".join(d * 2 for d in digits)
        return int(digits[0:2], 16), int(digits[2:4], 16), int(digits[4:6], 16)
    raise ValueError(text)


def rules_of(css: str) -> list[tuple[str, dict[str, str]]]:
    """Every rule's selector and declarations, with the rules inside a media query included."""
    css = re.sub(r"/\*.*?\*/", "", css, flags=re.S)
    found = []
    for selector, body in re.findall(r"([^{}]+)\{([^{}]*)\}", css):
        declarations = {}
        for part in body.split(";"):
            if ":" in part:
                key, value = part.split(":", 1)
                declarations[key.strip()] = value.strip()
        found.append((" ".join(selector.split()), declarations))
    return found


def tokens_of(css: str) -> dict[str, str]:
    root = {}
    for selector, declarations in rules_of(css):
        if selector == ":root":
            root.update({k: v for k, v in declarations.items() if k.startswith("--")})
    return root


def resolved(value: str, tokens: dict[str, str]) -> str:
    for _ in range(8):
        value = re.sub(r"var\((--[a-z0-9-]+)\)", lambda m: tokens[m.group(1)], value)
    return value


def solid_colours(value: str) -> list[tuple[int, int, int]]:
    """The plain colours in a value: a hex colour, or every stop of a gradient. Transparency and keywords have none."""
    return [rgb_of(h) for h in re.findall(r"#[0-9a-fA-F]{3,6}\b", value)]


def pairs_in(css: str) -> list[tuple[str, tuple[int, int, int], tuple[int, int, int]]]:
    """Each text colour against the background it is set with, or against the two page surfaces if it sets none."""
    tokens = tokens_of(css)
    surfaces = [
        rgb_of(resolved(tokens[n], tokens)) for n in ("--color-bg-primary", "--color-bg-secondary")
    ]
    pairs = []
    for selector, declarations in rules_of(css):
        text = declarations.get("color")
        if text is None or text.strip() in ("inherit", "currentColor") or selector == ":root":
            continue
        ink = solid_colours(resolved(text, tokens))
        if not ink:
            continue
        set_with = declarations.get("background") or declarations.get("background-color") or ""
        backgrounds = solid_colours(resolved(set_with, tokens)) or surfaces
        pairs += [(selector, i, b) for i in ink for b in backgrounds]
    return pairs


def test_every_text_colour_in_the_style_has_at_least_4_5_to_1_against_its_background():
    css = (STATIC / "app.css").read_text()
    pairs = pairs_in(css)
    assert len(pairs) > 40, "the check must really have found the pairs"
    selectors = {s for s, _, _ in pairs}
    for needed in (
        "body",
        "button",
        ".verdict",
        '.verdict.trusted, .verdict[data-status="TRUSTED"]',
        '.verdict[data-status="SELF_SIGNED_ONLY"]',
        "#warnings",
        ".demo-banner",
        ".panel.notice, .notice-line",
        ".site-footer",
        ".step",
        ".fine",
        "a",
    ):
        assert needed in selectors, needed
    faint = [(s, i, b, round(ratio(i, b), 2)) for s, i, b in pairs if ratio(i, b) < 4.5]
    assert not faint, faint


def test_each_meaning_colour_reads_on_its_own_tint_and_on_both_page_surfaces():
    tokens = tokens_of((STATIC / "app.css").read_text())
    pick = lambda name: rgb_of(resolved(tokens[name], tokens))  # noqa: E731
    surfaces = (pick("--color-bg-primary"), pick("--color-bg-secondary"))
    for meaning in ("good", "bad", "warn", "demo"):
        text, tint = pick(f"--color-{meaning}-text"), pick(f"--color-{meaning}-bg")
        assert ratio(text, tint) >= 4.5, meaning
        assert ratio(text, surfaces[0]) >= 4.5 and ratio(text, surfaces[1]) >= 4.5, meaning
    for plain in (
        "--color-text-primary",
        "--color-text-dim",
        "--color-accent",
        "--color-highlight",
    ):
        assert ratio(pick(plain), surfaces[0]) >= 4.5 and ratio(pick(plain), surfaces[1]) >= 4.5, (
            plain
        )


def test_the_lines_that_mark_a_control_or_the_focus_have_at_least_3_to_1():
    tokens = tokens_of((STATIC / "app.css").read_text())
    pick = lambda name: rgb_of(resolved(tokens[name], tokens))  # noqa: E731
    for surface in ("--color-bg-primary", "--color-bg-secondary"):
        assert ratio(pick("--color-accent"), pick(surface)) >= 3
        assert ratio(pick("--color-border"), pick(surface)) >= 3
    css = (STATIC / "app.css").read_text()
    choice = css[css.index(".choice {") : css.index("}", css.index(".choice {"))]
    assert "border: 2px solid var(--color-border)" in choice


def test_the_pages_colour_checker_would_catch_a_faint_pair():
    faint = ".x { color: #9ca3af; background: #ffffff; } :root { --color-bg-primary: #fff; --color-bg-secondary: #f7f9fc; }"
    assert [r for _, i, b in pairs_in(faint) if (r := ratio(i, b)) < 4.5]
    assert ratio((0, 0, 0), (255, 255, 255)) == pytest.approx(21)


def test_the_unavailable_page_reads_well_too():
    style = fallback_module._STYLE + ":root{--color-bg-primary:#fff;--color-bg-secondary:#f7f9fc}"
    pairs = pairs_in(style)
    assert len(pairs) >= 3
    assert not [(s, i, b) for s, i, b in pairs if ratio(i, b) < 4.5]


# ----------------------------------------------------------------------------- the unavailable page looks the same without any file


def test_the_unavailable_page_has_the_look_and_loads_nothing(fallback_page):
    text = fallback_page
    style = fallback_module._STYLE
    assert "url(" not in style and "@import" not in style and "//" not in style
    for stack in ("system-ui", "ui-monospace", "sans-serif"):
        assert stack in style, stack
    assert "<svg " in text and "xmlns" not in text and 'aria-hidden="true"' in text
    assert '<header class="bar">' in text and "<main>" in text and "<footer>" in text
    assert "VaultBytes" in text and "&copy; 2026 VaultBytes Innovations Ltd." in text
    assert 'class="rule"' in text
    assert text.count("<style>") == 1
    assert "<img" not in text and "<link" not in text and "<script" not in text
    assert re.search(r"font:[^;}]*'Segoe UI'", style)


@pytest.fixture
def fallback_page() -> str:
    return fallback_module.PAGE.decode()


def test_the_script_respects_reduced_motion_when_it_scrolls():
    script = (
        Path(__file__).resolve().parents[1] / "regaudit_portal" / "static" / "app.js"
    ).read_text()
    assert "prefers-reduced-motion" in script and "scrollIntoView" in script
    assert 'behavior: "smooth"' not in script.replace('reduceMotion ? "auto" : "smooth"', "")
