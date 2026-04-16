# Font assets for PDF reports

`app/templates/report_pdf.html` references the following files via `@font-face`:

| File             | Weight | Style  | Role                  |
|------------------|--------|--------|-----------------------|
| `Aptos.ttf`         | 400    | normal | Body copy             |
| `Aptos-Bold.ttf`    | 700    | normal | Headings, bold emphasis |
| `Aptos-Italic.ttf`  | 400    | italic | Emphasis              |
| `Aptos-Display.ttf` | 400    | normal | Cover + large titles (`font-family: "Aptos Display"`) |

## Installation

Aptos is Microsoft's proprietary corporate font. It ships with Microsoft 365 /
Office 365 installations and is not available under an open license (no OFL, no
Debian package). You have to copy the TTF files into this directory manually.

On macOS, a typical source is:
```
/Applications/Microsoft Word.app/Contents/Resources/DFonts/
```
or via `~/Library/Fonts/`.

On Windows:
```
C:\Windows\Fonts\Aptos*.ttf
```

Copy the required TTF files into this directory and commit them *only* if your
organization's license permits redistribution of the fonts within your internal
tooling.

## Fallback

If any of the files are missing, WeasyPrint silently falls back to the next
entry in the CSS `font-family` stack:
`"Aptos", "Aptos Display", "Segoe UI", "DejaVu Sans", sans-serif`.

DejaVu Sans is always present in the Docker image (`fonts-dejavu-core` package),
so reports will always render — but without Aptos they won't match the
company-internal style.
