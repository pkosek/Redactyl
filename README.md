# Redactyl

Local document redaction tool — process PDFs, images, and plain text entirely on your machine. No uploads. No telemetry.

---

## What it does
Redactyl searches documents for **exact strings** and **regular expressions** you define in `sensitive.yml` (or `sensitive.yaml`) and renders output with those matches permanently obscured (black boxes). It supports:

- **PDFs**
  - Text‑based PDFs: text is read directly.
  - Image‑only / scanned PDFs: pages are rasterised and passed to OCR.
- **Images**: PNG, JPG/JPEG and other common formats (via Pillow/OpenCV).
- **Plain text** files (simple text processing).

> Tip: Output is written with overlays baked in (no removable “annotations”).

---

## How it works (high level)
1. Load `sensitive.yml` (rules) — either from the app folder, next to the executable, or the bundled default.
2. For **PDFs with a text layer**, Redactyl applies rules directly to extracted text.
3. For **images / scanned pages**, Redactyl uses OCR (EasyOCR by default; Tesseract as fallback) to find words + bounding boxes, then applies rules.
4. Matching regions are drawn over and a new redacted file is produced.

---

## UI controls
- **YAML rules** – The large text area contains the active `sensitive.yml`. Edit and save to apply.
- **OCR sensitivity (confidence)** – Minimum detection confidence for OCR text (0–100). Lower = catch more but risk false positives; higher = stricter. If a target word isn’t being redacted from a photo/scan, try lowering this.
- **DPI slider (for scanned PDFs/images)** – Controls rasterisation resolution when converting pages to images for OCR/redaction. Higher DPI improves OCR but increases processing time and output size. 200–300 DPI is a good starting point.
- **Debug mode** – When enabled, the app shows all matches it found (exact + regex) with their bounding boxes and confidences. Use this to understand **why** something did or didn’t get redacted before exporting a final file.
- **Stop Server** – Red button in the UI that gracefully shuts down the local server.

---

## Running Redactyl (dev)
**Prereqs:** Python 3.11/3.12 recommended (PyMuPDF wheels). Tesseract binary optional (fallback OCR). On macOS: `brew install tesseract` (if you want Tesseract).

```bash
# clone
git clone https://github.com/<you>/Redactyl.git
cd Redactyl

# create venv (3.11 preferred)
python3.11 -m venv .venv
source .venv/bin/activate
pip install --upgrade pip
pip install -r requirements.txt

# run
python app/main.py
```
Now open `http://127.0.0.1:8000` (the browser should open automatically).

### Power users – change the port
You can override the default port (8000):
- **CLI:** `python app/main.py 9001`
- **Env var:** `REDACTYL_PORT=9001 python app/main.py`

> The app will also try the next available ports if the requested one is busy.

---

## Packaging (optional)
Build a standalone desktop app with PyInstaller (macOS example):

```bash
pyinstaller --onefile --windowed --name Redactyl \
  --icon Redactyl.icns \
  --add-data "app/icon.png:icon.png" \
  --add-data "sensitive.yaml:sensitive.yaml" \
  app/main.py
```
- Distribute the resulting `dist/Redactyl.app` (mac) or `dist/Redactyl.exe` (Windows, build on Windows).
- To override rules for end‑users, place `sensitive.yml` **next to the executable** or inside the app’s `Contents/Resources`.

---

## `sensitive.yml` quick format
```yaml
version: 1
normalization:
  case_insensitive: true
  strip_accents: true
  collapse_whitespace: true
  ignore_chars: "-_.()"   # ignored for *exact* matches only; regex sees raw text
regex:
  - '(?i)(?<![A-Z0-9._%+-])[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}(?![A-Z0-9._%+-])'  # emails
  - '(?i)\b\d{2,4}[ -]?\d{3}[ -]?\d{3,4}\b'                                        # phones (example)
exact:
  - "John Smith"
  - "National Insurance"
```

---

## Notes
- **OCR engine**: EasyOCR is used when available (lazy‑loaded for fast startup); the Tesseract path remains as a fallback.
- **Privacy**: All processing stays on your machine.
- **Performance**: Scans with security backgrounds (e.g., passports) may need a higher DPI and lower OCR threshold.
