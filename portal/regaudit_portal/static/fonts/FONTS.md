# Fonts

The portal's pages use three typefaces. They are files in this folder and the portal serves them itself, from
`/static/fonts/`. A page never asks another computer for a font, and the content policy (`font-src 'self'`) would stop it.

Each file is the Latin subset, as a variable font, in WOFF2, taken unchanged from the `@fontsource-variable` package of
that name at the version shown.

| Typeface | Used for | Package and version | File | SHA-256 of the file |
| --- | --- | --- | --- | --- |
| Inter | text | `@fontsource-variable/inter` 5.3.0 | `inter-latin-wght-normal.woff2` | `3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62` |
| Space Grotesk | headings | `@fontsource-variable/space-grotesk` 5.3.0 | `space-grotesk-latin-wght-normal.woff2` | `0640890476fc1198ab4de571fb658de443c4d85b66466ec09534a8737ab1ce9d` |
| JetBrains Mono | wordmark, navigation, buttons, codes | `@fontsource-variable/jetbrains-mono` 5.3.0 | `jetbrains-mono-latin-wght-normal.woff2` | `18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e` |

## Licence

All three are licensed under the SIL Open Font License, Version 1.1. The text that came with each is next to its font:

| Typeface | Licence text | SHA-256 of the text |
| --- | --- | --- |
| Inter | `inter-OFL.txt` | `3b0a5fca3d17942cde889069889dedbbbd075e9b599968c82a95f4d944e9b345` |
| Space Grotesk | `space-grotesk-OFL.txt` | `18a4de52385f6b988782639d5d0cc1326e5a8c2de9a7f01d7b20d9aedcc60943` |
| JetBrains Mono | `jetbrains-mono-OFL.txt` | `403581b69dac5cff4079205e01c6b467e56af449ecbd7247693ddb1baafa005b` |

The fonts are included as they were published, not modified and not renamed, and they are not sold on their own.

## Where they came from, and how to fetch them again

Each font is at `https://cdn.jsdelivr.net/npm/@fontsource-variable/<name>@5.3.0/files/<name>-latin-wght-normal.woff2`
and each licence text at `https://cdn.jsdelivr.net/npm/@fontsource-variable/<name>@5.3.0/LICENSE`, where `<name>` is
`inter`, `space-grotesk` or `jetbrains-mono`. To fetch them again and check them against the digests above, run this in
this folder:

```
for name in inter space-grotesk jetbrains-mono; do
  curl -fsSLO "https://cdn.jsdelivr.net/npm/@fontsource-variable/${name}@5.3.0/files/${name}-latin-wght-normal.woff2"
  curl -fsSL -o "${name}-OFL.txt" "https://cdn.jsdelivr.net/npm/@fontsource-variable/${name}@5.3.0/LICENSE"
done
shasum -a 256 -c <<'EOF'
3100e775e8616cd2611beecfa23a4263d7037586789b43f035236a2e6fbd4c62  inter-latin-wght-normal.woff2
0640890476fc1198ab4de571fb658de443c4d85b66466ec09534a8737ab1ce9d  space-grotesk-latin-wght-normal.woff2
18be452724bfdc236c074ca94a249a7f41a86752c7d04ab258ce9ed5651f6a7e  jetbrains-mono-latin-wght-normal.woff2
3b0a5fca3d17942cde889069889dedbbbd075e9b599968c82a95f4d944e9b345  inter-OFL.txt
18a4de52385f6b988782639d5d0cc1326e5a8c2de9a7f01d7b20d9aedcc60943  space-grotesk-OFL.txt
403581b69dac5cff4079205e01c6b467e56af449ecbd7247693ddb1baafa005b  jetbrains-mono-OFL.txt
EOF
```

A test in the portal's test suite checks that the three font files and the three licence texts are in the package.
