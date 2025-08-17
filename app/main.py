#!/usr/bin/env python3
"""
Simple redaction web app.

This application exposes a minimal HTTP server for uploading documents
and redacting sensitive information.  Sensitive information is defined
in a YAML configuration.  Users can override this configuration via
the web form before executing redaction.  Supported input types are
plain text files, PDF documents and raster images (PNG/JPG/JPEG).

The server deliberately avoids third-party web frameworks (e.g. Flask)
to remain lightweight and install-free.  It relies solely on Python's
standard library for HTTP handling and uses PyMuPDF for PDF
manipulation and OpenCV for rudimentary image pattern matching.  No
external network access is required.
"""

import io
import os
import re
import sys
import base64
import yaml
import html
import time
import mimetypes
import unicodedata
import webbrowser
import threading
import socket
import subprocess
from pathlib import Path
# --- Resource helpers for sensitive.yaml (override and bundle support) ---

def resource_path(rel: str) -> Path:
    """
    Resolve a data file whether running from source or a PyInstaller bundle.
    """
    base = Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))
    return base / rel



def _open_url_robust(url: str) -> None:
    """Try multiple strategies to open the user's default browser."""
    try:
        webbrowser.open(url, new=1)
        return
    except Exception:
        pass
    # macOS fallback: use the 'open' command
    if sys.platform == 'darwin':
        try:
            subprocess.Popen(['open', url])
            return
        except Exception:
            pass
    # Windows fallback
    if sys.platform.startswith('win'):
        try:
            os.startfile(url)  # type: ignore[attr-defined]
            return
        except Exception:
            pass


def _exe_dir() -> Path:
    """Return the directory of the running executable (PyInstaller) or this file."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

def load_default_yaml() -> str:
    """
    Load sensitive rules with override support.

    Order:
      1) ./sensitive.yaml or ./sensitive.yml         (current working directory)
      2) <exe_dir>/sensitive.yaml or .yml            (inside bundle MacOS/ or next to onefile exe)
      3) <exe_dir>/../Resources/sensitive.(yaml|yml) (bundle Resources)
      4) <bundle-parent>/sensitive.(yaml|yml)        (next to the .app bundle)
      5) bundled resource via PyInstaller             (resource_path)
    """
    names = ("sensitive.yaml", "sensitive.yml")

    # 1) CWD override
    for name in names:
        p = Path.cwd() / name
        if p.exists():
            return p.read_text(encoding="utf-8")

    exe_dir = _exe_dir()

    # 2) Next to the executable (MacOS/ or onefile exe dir)
    for name in names:
        p = exe_dir / name
        if p.exists():
            return p.read_text(encoding="utf-8")

    # 3) Inside app bundle Resources/
    try:
        contents = exe_dir.parent  # .../Contents
        resources = contents / "Resources"
        for name in names:
            p = resources / name
            if p.exists():
                return p.read_text(encoding="utf-8")
    except Exception:
        pass

    # 4) Next to the .app (folder that contains the bundle)
    try:
        # exe_dir = .../Your.app/Contents/MacOS
        bundle_parent = exe_dir.parents[3]
        for name in names:
            p = bundle_parent / name
            if p.exists():
                return p.read_text(encoding="utf-8")
    except Exception:
        pass

    # 5) Bundled (_MEIPASS)
    for name in names:
        try:
            return resource_path(name).read_text(encoding="utf-8")
        except Exception:
            pass

    # Fallback
    return "version: 1\nnormalization:\n  case_insensitive: true\ntargets: {}"

from functools import partial
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlsplit
import cgi

import numpy as np  # required for image manipulation
from base64 import b64encode
import html

try:
    import fitz  # PyMuPDF
except ImportError:
    fitz = None

try:
    import cv2  # OpenCV for image handling
except ImportError:
    cv2 = None

try:
    # Optional: pytesseract for OCR-based image redaction.  If not available,
    # the application will fall back to naive template matching.
    import pytesseract  # type: ignore
except Exception:
    pytesseract = None

easyocr = None  # lazy-imported on first OCR use
_easyocr_reader = None  # cached EasyOCR reader instance

def _html_escape(s):
    """Safely escape HTML for debug output."""
    if s is None:
        return ""
    return html.escape(str(s))

def _img_bytes_to_data_url(img_bytes, mime="image/png"):
    """Convert raw image bytes to a data URL for embedding in HTML debug output."""
    if not img_bytes:
        return ""
    b64 = base64.b64encode(img_bytes).decode("ascii")
    return f"data:{mime};base64,{b64}"

def normalize_string(s: str, case_insensitive: bool = True, strip_accents: bool = True,
                    collapse_whitespace: bool = True, ignore_chars: str = "") -> str:
    """Normalize a string according to provided rules.

    Args:
        s: The input string.
        case_insensitive: Whether to lower-case the string.
        strip_accents: Whether to remove diacritical marks.
        collapse_whitespace: Whether to collapse runs of whitespace into a single space.
        ignore_chars: Characters to remove entirely from the string.

    Returns:
        A normalized string.
    """
    # Remove accents
    if strip_accents:
        s = ''.join(c for c in unicodedata.normalize('NFKD', s) if not unicodedata.combining(c))
    # Remove characters to ignore
    if ignore_chars:
        pattern = '[' + re.escape(ignore_chars) + ']'
        s = re.sub(pattern, '', s)
    # Collapse whitespace
    if collapse_whitespace:
        s = re.sub(r"\s+", ' ', s)
    # Case insensitive
    if case_insensitive:
        s = s.lower()
    return s


# Helper to normalize for regex matching, preserving punctuation (for regexes like emails)
def normalize_for_regex(s: str) -> str:
    """Normalize text for regex matching while preserving punctuation.

    Applies Unicode NFKC normalization, strips zero-width and BOM characters,
    and converts non-breaking spaces to regular spaces. This keeps characters
    like '@' and '.' intact so patterns such as email regexes continue to work.
    """
    if not isinstance(s, str):
        try:
            s = str(s)
        except Exception:
            return ""
    s = unicodedata.normalize("NFKC", s)
    # Remove zero-width / BOM / word-joiner category characters that often
    # appear in PDF text and break regexes without being visible.
    for ch in ("\u200b", "\u200c", "\u200d", "\ufeff", "\u2060"):
        s = s.replace(ch, "")
    # Replace non-breaking space with normal space
    s = s.replace("\u00a0", " ")
    return s

def _get_easyocr_reader():
    """Lazily create and cache an EasyOCR reader (CPU only)."""
    global easyocr, _easyocr_reader
    if _easyocr_reader is not None:
        return _easyocr_reader
    # allow opting out to speed startup or force Tesseract
    if os.environ.get("REDACTYL_DISABLE_EASYOCR") == "1":
        return None
    if easyocr is None:
        try:
            import easyocr as _easy
            easyocr = _easy
        except Exception:
            return None
    try:
        _easyocr_reader = easyocr.Reader(['en'], gpu=False)
    except Exception:
        _easyocr_reader = None
    return _easyocr_reader

def pattern_to_regex(pattern: str, ignore_chars: str) -> str:
    """
    Convert an exact literal ``pattern`` into a regular expression that tolerates
    characters listed in ``ignore_chars`` *between* every character of the pattern.

    This helper escapes each literal character in the pattern and inserts a
    character class built from ``ignore_chars`` and ``*`` between characters to
    permit an arbitrary number of these ignored characters.  Importantly, no
    ignore class is appended after the final character of the pattern to avoid
    consuming trailing punctuation (e.g. the period following a name).
    """
    # Normalize pattern into a string
    if not isinstance(pattern, str):
        try:
            pattern = str(pattern)
        except Exception:
            pattern = ""
    # Empty ignore list: escape pattern literally
    if not ignore_chars:
        return re.escape(pattern)
    # Build a character class from ignore chars
    ignore_class = '[' + re.escape(ignore_chars) + ']'
    parts: list[str] = []
    for idx, ch in enumerate(pattern):
        parts.append(re.escape(ch))
        # Only insert the ignore class between characters, not at the end
        if idx < len(pattern) - 1:
            parts.append(ignore_class + '*')
    return ''.join(parts)


def compile_sensitive_patterns(sensitive_config: dict) -> dict:
    """Compile sensitive configuration into regex patterns.
    
    Args:
        sensitive_config: Dictionary containing normalization rules and patterns
        
    Returns:
        Dictionary with compiled patterns and rules
    """
    # Fix indentation of nested dictionary access
    normalization = (sensitive_config or {}).get('normalization', {}) or {}
    ignore_chars = normalization.get('ignore_chars', '')
    case_insensitive = normalization.get('case_insensitive', True)
    strip_accents = normalization.get('strip_accents', True) 
    collapse_whitespace = normalization.get('collapse_whitespace', True)

    # Fix list comprehensions indentation
    exact_labeled = []
    regex_labeled = []
    
    # Fix nested loop indentation
    root_cat = 'root'
    for val in (sensitive_config or {}).get('exact', []) or []:
        if isinstance(val, (str, int, float)) or val is None:
            s = '' if val is None else str(val)
            norm = normalize_string(
                s,
                case_insensitive=case_insensitive,
                strip_accents=strip_accents, 
                collapse_whitespace=collapse_whitespace,
                ignore_chars=ignore_chars
            )
            if norm:
                exact_labeled.append((norm, root_cat))

    # Fix regex compilation indentation                
    for rx in (sensitive_config or {}).get('regex', []) or []:
        if not isinstance(rx, str):
            try:
                rx = str(rx)
            except Exception:
                continue
        try:
            regex_labeled.append((re.compile(rx, re.IGNORECASE), root_cat))
        except re.error:
            pass

    # Hierarchical "targets"
    targets = (sensitive_config or {}).get('targets', {}) or {}
    for cat, rules in targets.items():
        if not isinstance(rules, dict):
            continue
        # exact
        for val in rules.get('exact', []) or []:
            if isinstance(val, (str, int, float)) or val is None:
                s = '' if val is None else str(val)
                norm = normalize_string(
                    s,
                    case_insensitive=case_insensitive,
                    strip_accents=strip_accents,
                    collapse_whitespace=collapse_whitespace,
                    ignore_chars=ignore_chars
                )
                if norm:
                    exact_labeled.append((norm, cat))
        # regex
        for rx in rules.get('regex', []) or []:
            if not isinstance(rx, str):
                try:
                    rx = str(rx)
                except Exception:
                    continue
            try:
                regex_labeled.append((re.compile(rx, re.IGNORECASE), cat))
            except re.error:
                pass

    # Dedupe exact by normalized value (keep first category encountered)
    dedup_exact = []
    seen = set()
    for norm, cat in exact_labeled:
        if norm in seen:
            continue
        seen.add(norm)
        dedup_exact.append((norm, cat))
    exact_labeled = dedup_exact

    # Build tolerant regexes for exact patterns (for plain-text replacement)
    text_replacements_labeled = []
    text_replacements = []
    for norm, cat in exact_labeled:
        rx_str = pattern_to_regex(norm, ignore_chars)
        if not isinstance(rx_str, str) or not rx_str:
            continue
        try:
            rx_comp = re.compile(rx_str, re.IGNORECASE)
        except re.error:
            continue
        text_replacements_labeled.append((rx_comp, cat))
        text_replacements.append(rx_comp)

    return {
        'exact_patterns': [p for p, _ in exact_labeled],
        'exact_patterns_labeled': exact_labeled,              # [(pattern, category)]
        'regex_patterns': [r for r, _ in regex_labeled],      # [compiled]
        'regex_patterns_labeled': regex_labeled,              # [(compiled, category)]
        'text_replacements': text_replacements,               # [compiled]
        'text_replacements_labeled': text_replacements_labeled,  # [(compiled, category)]
        'normalization': normalization
    }


def redact_text_content(content: str, compiled: dict) -> str:
    """Redact sensitive patterns from a text string.

    This helper collects all matches from both the tolerant exact patterns and
    regex patterns, merges overlapping intervals and performs a single pass
    replacement.  A unified replacement avoids nested substitutions where the
    output of one pattern would be processed again by another pattern (e.g.
    replacing inside an existing ``[REDACTED]`` marker).  It also takes care
    to add a space before or after a replacement only when the adjacent
    character is alphanumeric.  Punctuation immediately adjacent to a
    redacted token is preserved without an extra space.

    Args:
        content: The original text content.
        compiled: Result of ``compile_sensitive_patterns()``.

    Returns:
        The redacted text content.
    """
    if not content:
        return content or ""
    matches = []  # list of (start, end) tuples to redact
    # Collect matches for tolerant exact patterns
    for rx in compiled.get('text_replacements', []):
        try:
            for m in rx.finditer(content):
                if m.start() < m.end():
                    matches.append((m.start(), m.end()))
        except Exception:
            # If a regex fails during search, skip it
            continue
    # Collect matches for regex patterns
    for rx in compiled.get('regex_patterns', []):
        try:
            for m in rx.finditer(content):
                if m.start() < m.end():
                    matches.append((m.start(), m.end()))
        except Exception:
            continue
    if not matches:
        return content
    # Sort and merge overlapping/adjacent intervals
    matches.sort(key=lambda x: x[0])
    merged = []
    for start, end in matches:
        if not merged:
            merged.append([start, end])
            continue
        prev_start, prev_end = merged[-1]
        if start <= prev_end:
            # overlaps or touches; extend
            merged[-1][1] = max(prev_end, end)
        else:
            merged.append([start, end])
    # Perform replacement from end to start to avoid offset changes
    result = content
    for start, end in reversed(merged):
        result = result[:start] + '[REDACTED]' + result[end:]
    # After inserting markers, add spaces around them only when adjacent
    # characters are alphanumeric (word characters).  This avoids adding
    # unwanted spaces before punctuation like commas or periods.
    # Space before marker
    result = re.sub(r'(?<=\w)\[REDACTED\]', ' [REDACTED]', result)
    # Space after marker
    result = re.sub(r'\[REDACTED\](?=\w)', '[REDACTED] ', result)
    return result


def find_pdf_redaction_rects(page, compiled_patterns: dict):
    """Locate sensitive text on a PDF page using word extraction.

    This function scans the words on the given page and identifies sequences of
    words whose normalized concatenation exactly matches a sensitive pattern.
    Regex patterns are applied on individual normalized words.  The returned
    rectangles can be used directly as redaction annotations.

    Args:
        page: A PyMuPDF page object.
        compiled_patterns: Output of compile_sensitive_patterns().

    Returns:
        List of fitz.Rect objects marking areas to redact.
    """
    rects = []
    # extract words: list of (x0, y0, x1, y1, text, block_no, line_no, word_no)
    try:
        words = page.get_text('words')
    except Exception:
        return rects
    if not words:
        return rects
    normalization = compiled_patterns.get('normalization', {})
    ignore_chars = normalization.get('ignore_chars', '')
    case_insensitive = normalization.get('case_insensitive', True)
    strip_accents = normalization.get('strip_accents', True)
    collapse_whitespace = normalization.get('collapse_whitespace', True)

    # Precompute normalized words
    normalized_words = []
    for w in words:
        text = w[4]
        norm = normalize_string(text, case_insensitive=case_insensitive,
                                strip_accents=strip_accents,
                                collapse_whitespace=collapse_whitespace,
                                ignore_chars=ignore_chars)
        normalized_words.append(norm)

    # Build exact patterns list
    exact_patterns = compiled_patterns.get('exact_patterns', [])
    # Map patterns to their lengths (in normalized form)
    pattern_lens = {p: len(p) for p in exact_patterns}

    # Search for exact patterns across word sequences
    for pat, pat_len in pattern_lens.items():
        if not pat:
            continue
        nwords = len(words)
        for i in range(nwords):
            combined = normalized_words[i]
            if not pat.startswith(combined):
                # Quick elimination: if pattern doesn't start with first word
                continue
            if len(combined) > pat_len:
                continue
            # extend across following words until length >= pat_len
            j = i + 1
            while len(combined) < pat_len and j < nwords:
                combined += normalized_words[j]
                j += 1
            if combined == pat:
                # get bounding box for words i to j-1
                x0 = min(words[k][0] for k in range(i, j))
                y0 = min(words[k][1] for k in range(i, j))
                x1 = max(words[k][2] for k in range(i, j))
                y1 = max(words[k][3] for k in range(i, j))
                rects.append(fitz.Rect(x0, y0, x1, y1))

    # Apply regex patterns on individual words using the *original* word text
    # (not the fully normalized/stripped version), so punctuation like '@' and
    # '.' remains available to the regex (e.g., email addresses).
    for rx in compiled_patterns.get('regex_patterns', []):
        for idx, w in enumerate(words):
            raw_word = normalize_for_regex(w[4])
            try:
                if rx.search(raw_word):
                    x0, y0, x1, y1 = words[idx][:4]
                    rects.append(fitz.Rect(x0, y0, x1, y1))
            except Exception:
                continue
    return rects


def redact_pdf(data: bytes, compiled: dict) -> bytes:
    """Redact sensitive information from a PDF file.

    Args:
        data: Binary contents of the PDF.
        compiled: Output of compile_sensitive_patterns().

    Returns:
        Redacted PDF binary data.
    """
    if fitz is None:
        raise RuntimeError("PyMuPDF is not available in this environment.")
    # Load from bytes via in-memory buffer
    doc = fitz.open(stream=data, filetype='pdf')
    for page in doc:
        # First try text-layer based redactions
        rects = find_pdf_redaction_rects(page, compiled)
        if not rects:
            # OCR fallback for image-only pages
            rects = _ocr_pdf_page_rects(
                page,
                compiled,
                ocr_min_conf=compiled.get('normalization', {}).get('ocr_min_conf', 60),
                dpi=compiled.get('normalization', {}).get('pdf_ocr_dpi', 150)
            )
        for rect in rects:
            page.add_redact_annot(rect, fill=(0, 0, 0))
        if rects:
            page.apply_redactions()
    # Save redacted PDF to bytes
    buf = doc.tobytes()
    doc.close()
    return buf



def detect_image_matches(img, compiled: dict, ocr_min_conf: int = 60):
    """
    Return detailed OCR matches for an image.

    This helper first attempts to use EasyOCR (if installed) to detect
    text and their bounding boxes, because EasyOCR is more tolerant of
    noisy backgrounds such as passports.  The results are filtered by
    ``ocr_min_conf`` (multiplied by 100 for EasyOCR, since its confidence
    scores are 0–1).  If EasyOCR is not available or yields no matches,
    the function falls back to using pytesseract.  When neither OCR
    engine is available, an empty list is returned, indicating that
    no sensitive information could be detected in the image.

    Args:
        img: A BGR image as a NumPy array.
        compiled: A dictionary of compiled patterns returned by
            ``compile_sensitive_patterns()``.
        ocr_min_conf: Minimum confidence threshold (0–100).  Words with
            confidence below this value are ignored.

    Returns:
        A list of match dictionaries with keys ``text``, ``conf`` (0–100),
        ``bbox`` (x0,y0,x1,y1), ``match_type`` and ``category``.
    """
    matches: list[dict] = []
    normalization = compiled.get('normalization', {})
    ignore_chars = normalization.get('ignore_chars', '')
    case_insensitive = normalization.get('case_insensitive', True)
    strip_accents = normalization.get('strip_accents', True)
    collapse_whitespace = normalization.get('collapse_whitespace', True)

    # 1. Try EasyOCR if available (lazy import / cached)
    reader = _get_easyocr_reader()
    if reader is not None:
        try:
            ocr_results = reader.readtext(img)
        except Exception:
            ocr_results = None
        if ocr_results:
            for bbox, text, conf in ocr_results:
                conf_pct = float(conf) * 100.0  # EasyOCR returns 0..1
                if conf_pct < ocr_min_conf:
                    continue
                clean = normalize_string(
                    text,
                    case_insensitive=case_insensitive,
                    strip_accents=strip_accents,
                    collapse_whitespace=collapse_whitespace,
                    ignore_chars=ignore_chars
                )
                if not clean:
                    continue
                xs = [pt[0] for pt in bbox]
                ys = [pt[1] for pt in bbox]
                x0, y0, x1, y1 = int(min(xs)), int(min(ys)), int(max(xs)), int(max(ys))
                bbox_tuple = (x0, y0, x1, y1)
                matched = False
                for pat, cat in compiled.get('exact_patterns_labeled', []):
                    if clean == pat:
                        matches.append({
                            'text': text,
                            'conf': conf_pct,
                            'bbox': bbox_tuple,
                            'match_type': 'exact',
                            'category': cat
                        })
                        matched = True
                        break
                if matched:
                    continue
                for rx, cat in compiled.get('regex_patterns_labeled', []):
                    try:
                        # apply regex to minimally-normalized text (keep punctuation)
                        if rx.search(normalize_for_regex(text)):
                            matches.append({
                                'text': text,
                                'conf': conf_pct,
                                'bbox': bbox_tuple,
                                'match_type': 'regex',
                                'category': cat
                            })
                            break
                    except Exception:
                        continue
        if matches:
            return matches

    # 2. Fall back to pytesseract if available
    if pytesseract is not None:
        try:
            ocr_data = pytesseract.image_to_data(img, output_type=pytesseract.Output.DICT)
        except Exception:
            ocr_data = None
        if ocr_data:
            n = len(ocr_data.get('text', []))
            for i in range(n):
                word = (ocr_data['text'][i] or '').strip()
                if not word:
                    continue
                try:
                    conf = float(ocr_data['conf'][i])
                except Exception:
                    conf = -1.0
                if conf < ocr_min_conf:
                    continue
                clean = normalize_string(
                    word,
                    case_insensitive=case_insensitive,
                    strip_accents=strip_accents,
                    collapse_whitespace=collapse_whitespace,
                    ignore_chars=ignore_chars
                )
                if not clean:
                    continue
                x = int(ocr_data['left'][i])
                y = int(ocr_data['top'][i])
                w = int(ocr_data['width'][i])
                h = int(ocr_data['height'][i])
                bbox = (x, y, x + w, y + h)
                matched = False
                for pat, cat in compiled.get('exact_patterns_labeled', []):
                    if clean == pat:
                        matches.append({
                            'text': word,
                            'conf': conf,
                            'bbox': bbox,
                            'match_type': 'exact',
                            'category': cat
                        })
                        matched = True
                        break
                if matched:
                    continue
                for rx, cat in compiled.get('regex_patterns_labeled', []):
                    try:
                        if rx.search(clean):
                            matches.append({
                                'text': word,
                                'conf': conf,
                                'bbox': bbox,
                                'match_type': 'regex',
                                'category': cat
                            })
                            break
                    except Exception:
                        continue
            if matches:
                return matches

    # 3. No OCR engine available or no matches found
    return matches


def find_image_rects(img, compiled: dict, ocr_min_conf: int = 60) -> list:
    dets = detect_image_matches(img, compiled, ocr_min_conf=ocr_min_conf)
    return [m['bbox'] for m in dets]
def find_pdf_matches(page, compiled_patterns: dict):
    """
    Return detailed matches for a PDF page. Items are:
      { 'text': str, 'bbox': (x0,y0,x1,y1), 'match_type': 'exact'|'regex' }
    """
    details = []
    try:
        words = page.get_text('words')
    except Exception:
        return details
    if not words:
        return details

    normalization = compiled_patterns.get('normalization', {})
    ignore_chars = normalization.get('ignore_chars', '')
    case_insensitive = normalization.get('case_insensitive', True)
    strip_accents = normalization.get('strip_accents', True)
    collapse_whitespace = normalization.get('collapse_whitespace', True)

    normalized_words = []
    for w in words:
        text = w[4]
        norm = normalize_string(text, case_insensitive=case_insensitive,
                                strip_accents=strip_accents,
                                collapse_whitespace=collapse_whitespace,
                                ignore_chars=ignore_chars)
        normalized_words.append(norm)

    exact_patterns = compiled_patterns.get('exact_patterns', [])
    pattern_lens = {p: len(p) for p in exact_patterns}

    for pat, pat_len in pattern_lens.items():
        if not pat:
            continue
        nwords = len(words)
        for i in range(nwords):
            combined = normalized_words[i]
            if not pat.startswith(combined):
                continue
            if len(combined) > pat_len:
                continue
            j = i + 1
            while len(combined) < pat_len and j < nwords:
                combined += normalized_words[j]
                j += 1
            if combined == pat:
                x0 = min(words[k][0] for k in range(i, j))
                y0 = min(words[k][1] for k in range(i, j))
                x1 = max(words[k][2] for k in range(i, j))
                y1 = max(words[k][3] for k in range(i, j))
                original = " ".join(words[k][4] for k in range(i, j))
                cat = next((c for p,c in compiled_patterns.get('exact_patterns_labeled', []) if p == pat), 'exact')
                details.append({'text': original, 'bbox': (x0,y0,x1,y1), 'match_type': 'exact', 'category': cat})

    for rx, cat in compiled_patterns.get('regex_patterns_labeled', []):
        for idx, w in enumerate(words):
            raw_word = normalize_for_regex(w[4])
            try:
                if rx.search(raw_word):
                    x0, y0, x1, y1 = words[idx][:4]
                    details.append({'text': w[4], 'bbox': (x0,y0,x1,y1), 'match_type': 'regex', 'category': cat})
            except Exception:
                continue
    return details

def _ocr_pdf_page_rects(page, compiled: dict, ocr_min_conf: int = 60, dpi: int = 150):
    """Return list of fitz.Rect for OCR-detected matches on a PDF page."""
    if fitz is None or cv2 is None:
        return []
    # Render page and convert to an OpenCV-friendly image
    scale = dpi / 72.0
    pix = page.get_pixmap(matrix=fitz.Matrix(scale, scale))
    import numpy as _np
    img = _np.frombuffer(pix.samples, dtype=_np.uint8).reshape(pix.height, pix.width, pix.n)
    img = img.copy()
    if pix.n == 4:
        img = cv2.cvtColor(img, cv2.COLOR_RGBA2BGR)
    elif pix.n == 3:
        img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
    # Detect matches with existing image OCR pipeline
    dets = detect_image_matches(img, compiled, ocr_min_conf=ocr_min_conf)
    if not dets:
        return []
    # Map pixel bbox -> page coordinate bbox
    page_w = float(page.rect.width)
    page_h = float(page.rect.height)
    sx = page_w / float(pix.width or 1)
    sy = page_h / float(pix.height or 1)
    rects = []
    for d in dets:
        x0, y0, x1, y1 = d['bbox']
        rects.append(fitz.Rect(x0 * sx, y0 * sy, x1 * sx, y1 * sy))
    return rects

def redact_image(data: bytes, compiled: dict, img_format: str, ocr_min_conf: int = 60) -> bytes:
    """Redact sensitive information from an image file.

    Args:
        data: Binary image data.
        compiled: Output of compile_sensitive_patterns().
        img_format: Format string (e.g. 'png', 'jpg') to encode output.

    Returns:
        Redacted image binary data.
    """
    if cv2 is None:
        raise RuntimeError("OpenCV is not available in this environment.")
    # decode image
    image_array = cv2.imdecode(np.frombuffer(data, dtype=np.uint8), cv2.IMREAD_COLOR)
    if image_array is None:
        raise ValueError("Failed to decode image data")
    rects = find_image_rects(image_array, compiled, ocr_min_conf=ocr_min_conf)
    # draw black rectangles
    for (x0, y0, x1, y1) in rects:
        cv2.rectangle(image_array, (x0, y0), (x1, y1), (0, 0, 0), thickness=-1)
    # encode back to bytes
    ext = '.' + img_format.lower()
    ret, buf = cv2.imencode(ext, image_array)
    if not ret:
        raise RuntimeError("Failed to encode redacted image")
    return buf.tobytes()


class RedactionHandler(SimpleHTTPRequestHandler):
    """HTTP request handler for the redaction web app."""

    server_version = "RedactionHTTP/0.1"

    # Where to load the default sensitive YAML configuration from (bundled path)
    SENSITIVE_FILE = str(resource_path('sensitive.yaml'))

    def _load_default_yaml(self) -> str:
        """Load the default YAML file contents, with override-in-CWD support."""
        try:
            return load_default_yaml()
        except Exception:
            return "version: 1\nnormalization:\n  case_insensitive: true\ntargets: {}"

    def do_GET(self):
        """Serve the index page or static assets."""
        path = urlsplit(self.path).path  # strip query string (e.g., ?v=1)
        # Serve favicon for common paths (ico/png) using our packaged PNG
        if path in ('/favicon.ico', '/favicon.png'):
            try:
                icon_path = resource_path('icon.png')
                data = icon_path.read_bytes()
                self.send_response(HTTPStatus.OK)
                # Many browsers accept PNG for favicon.ico
                ctype = 'image/png'
                self.send_header('Content-Type', ctype)
                self.send_header('Content-Length', str(len(data)))
                # Avoid stubborn caching while iterating
                self.send_header('Cache-Control', 'no-store, max-age=0')
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_response(HTTPStatus.NO_CONTENT)
                self.end_headers()
            return
        # Graceful shutdown endpoint
        if path == '/shutdown':
            try:
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                body = "<html><body><h3>Shutting down…</h3></body></html>".encode('utf-8')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            finally:
                # Call shutdown on a separate thread so we don't block this request handler
                threading.Thread(target=self.server.shutdown, daemon=True).start()
            return
        # Serve app icon for browser tab
        if path == '/static/icon.png':
            try:
                icon_path = resource_path('icon.png')
                data = icon_path.read_bytes()
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-Type', 'image/png')
                self.send_header('Content-Length', str(len(data)))
                self.send_header('Cache-Control', 'no-store, max-age=0')
                self.end_headers()
                self.wfile.write(data)
            except Exception:
                self.send_error(HTTPStatus.NOT_FOUND, "icon not found")
            return
        if path == '/' or path.startswith('/index.html'):
            # Serve dynamic index page
            content = self.render_index_page()
            self.send_response(HTTPStatus.OK)
            self.send_header('Content-Type', 'text/html; charset=utf-8')
            self.send_header('Content-Length', str(len(content)))
            self.end_headers()
            self.wfile.write(content.encode('utf-8'))
            return
        # Otherwise fall back to default SimpleHTTPRequestHandler behavior
        return super().do_GET()

    def render_index_page(self) -> str:
        """Render the HTML for the upload/redaction page."""
        # Preload YAML content
        yaml_content = self._load_default_yaml()
        # HTML template; inline styles used for simplicity
        html = f"""
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>Redaction Tool</title>
    <link rel="icon" href="/static/icon.png?v=1" type="image/png">
    <link rel="shortcut icon" href="/favicon.ico?v=1">
    <link rel="apple-touch-icon" href="/static/icon.png?v=1">
    <style>
        body {{ font-family: sans-serif; margin: 2em; }}
        textarea {{ width: 100%; height: 200px; }}
        .container {{ max-width: 800px; margin: auto; }}
        .field {{ margin-bottom: 1em; }}
    </style>
</head>
<body>
<div class="container">
    <h1>Document Redaction Tool</h1>
    <div style="margin: 0.5em 0 1.5em 0; text-align:right;">
        <button type="button" id="shutdownBtn"
                style="background:#d9534f;color:#fff;border:none;border-radius:6px;padding:10px 14px;cursor:pointer;">
            Stop Server
        </button>
    </div>
    <script>
    (function(){{
        var btn = document.getElementById('shutdownBtn');
        if(btn){{
            btn.addEventListener('click', function(){{
                if(confirm('Stop the Redactyl server now?')){{
                    fetch('/shutdown').then(function(){{
                        document.body.innerHTML = '<div style=\\'font-family:sans-serif;margin:2em;\\'><h2>Server shutting down…</h2><p>You can close this tab.</p></div>';
                    }}).catch(function(){{}});
                }}
            }});
        }}
    }})();
    </script>
    <form action="/redact" method="POST" enctype="multipart/form-data">
        <div class="field">
            <label for="file">Select document (text, PDF, image):</label><br/>
            <input type="file" name="file" required>
        </div>
        <div class="field">
            <label for="yaml_content">Sensitive configuration (YAML):</label><br/>
            <textarea name="yaml_content">{yaml_content}</textarea>
        </div>
        <div class="field">
            <label for="ocr_conf">OCR minimum confidence: <span id="ocr_conf_val">60</span></label><br/>
            <input type="range" id="ocr_conf" name="ocr_conf" min="0" max="100" value="60"
                    oninput="document.getElementById('ocr_conf_val').textContent=this.value">
            <div style="font-size:0.9em;color:#666;">
                Only OCR words with confidence ≥ this value will be considered for redaction.
            </div>
            <label for="pdf_ocr_dpi">PDF OCR DPI:</label>
            <input type="range" id="pdf_ocr_dpi" name="pdf_ocr_dpi" min="72" max="300" value="150" step="10" oninput="document.getElementById('pdf_ocr_dpi_val').innerText=this.value">
            <span id="pdf_ocr_dpi_val">150</span>
            <br/>
        </div>
        <div class="field">
            <label><input type="checkbox" name="debug" value="1"> Debug (show detections, don't download)</label>
        </div>
        <button type="submit">Redact</button>
    </form>
</div>
</body>
</html>
"""
        return html

    def do_POST(self):
        """Handle file upload and redaction."""
        if self.path != '/redact':
            self.send_error(HTTPStatus.NOT_FOUND, "Unknown endpoint")
            return
        # Parse incoming form data
        ctype, pdict = cgi.parse_header(self.headers.get('Content-Type'))
        if ctype != 'multipart/form-data':
            self.send_error(HTTPStatus.BAD_REQUEST, "Invalid form submission")
            return
        pdict['boundary'] = bytes(pdict['boundary'], "utf-8")
        pdict['CONTENT-LENGTH'] = int(self.headers.get('Content-Length', 0))
        try:
            form = cgi.FieldStorage(fp=self.rfile, headers=self.headers, environ={'REQUEST_METHOD': 'POST'}, keep_blank_values=True)
        except Exception as e:
            self.send_error(HTTPStatus.BAD_REQUEST, f"Failed to parse form data: {e}")
            return
        # Retrieve the uploaded file; FieldStorage returns a FieldStorage object
        file_item = None
        if 'file' in form and isinstance(form['file'], cgi.FieldStorage):
            file_item = form['file']
        yaml_text = form.getfirst('yaml_content') or ''
        if file_item is None or getattr(file_item, 'file', None) is None:
            self.send_error(HTTPStatus.BAD_REQUEST, "No file uploaded")
            return
        file_data = file_item.file.read()
        filename = getattr(file_item, 'filename', None) or 'document'

        # Parse YAML configuration from the POST body; if invalid, inform the user.
        try:
            config = yaml.safe_load(yaml_text) if yaml_text.strip() else {}
        except yaml.YAMLError as e:
            self.send_error(HTTPStatus.BAD_REQUEST, f"Invalid YAML: {e}")
            return

        # IMPORTANT: compile patterns from the POSTed YAML (on-the-fly)
        compiled = compile_sensitive_patterns(config)

        # Read OCR confidence threshold from the form; default 60
        try:
            ocr_min_conf = int(form.getfirst('ocr_conf') or 60)
        except Exception:
            ocr_min_conf = 60
        ocr_min_conf = max(0, min(100, ocr_min_conf))
        
        # Read PDF OCR DPI (default 150), clamp to 72–300
        try:
            pdf_ocr_dpi = int(form.getfirst('pdf_ocr_dpi') or 150)
        except Exception:
            pdf_ocr_dpi = 150
        pdf_ocr_dpi = max(72, min(300, pdf_ocr_dpi))
        compiled['normalization'] = compiled.get('normalization', {})
        compiled['normalization']['ocr_min_conf'] = ocr_min_conf
        compiled['normalization']['pdf_ocr_dpi'] = pdf_ocr_dpi

        # Check if debug mode is enabled
        debug_mode = form.getfirst('debug') == '1'
        # Determine file type
        ext = os.path.splitext(filename)[1].lower()
        # fallback mime type
        mime, _ = mimetypes.guess_type(filename)
        try:
            debug_mode = form.getfirst('debug') == '1'
            ext = os.path.splitext(filename)[1].lower()
            mime, _ = mimetypes.guess_type(filename)

            if debug_mode:
                # Build a debug HTML report showing what will be redacted
                report_parts = []
                report_parts.append("<html><head><meta charset='utf-8'><title>Redaction Debug</title>")
                report_parts.append("<style>body{font-family:sans-serif;padding:1rem} table{border-collapse:collapse} td,th{border:1px solid #ccc;padding:4px 6px} .tag{display:inline-block;padding:2px 6px;background:#eee;border-radius:4px;margin-left:6px}</style>")
                report_parts.append("</head><body>")
                report_parts.append(f"<h2>Debug report for: {_html_escape(filename)}</h2>")
                report_parts.append(f"<p>OCR min confidence: <b>{ocr_min_conf}</b></p>")
                report_parts.append(f"<p>PDF OCR DPI: <b>{compiled.get('normalization', {}).get('pdf_ocr_dpi', 150)}</b></p>")

                if ext in ['.txt', '.text'] or (mime and mime.startswith('text')):
                    text_content = file_data.decode('utf-8', errors='ignore')
                    # Gather matches (positions) without mutating text
                    matches = []
                    for rx, cat in compiled['text_replacements_labeled']:
                        for m in rx.finditer(text_content):
                            matches.append({'span': m.span(), 'text': m.group(0), 'type': 'exact', 'category': cat})
                    for rx, cat in compiled['regex_patterns_labeled']:
                        for m in rx.finditer(text_content):
                            matches.append({'span': m.span(), 'text': m.group(0), 'type': 'regex', 'category': cat})
                    report_parts.append(f"<p>Detected matches: <b>{len(matches)}</b></p>")
                    if matches:
                        report_parts.append("<table><tr><th>Type</th><th>Category</th><th>Match</th><th>Start..End</th></tr>")
                        for m in matches[:500]:
                            report_parts.append(f"<tr><td>{m['type']}</td><td>{_html_escape(m.get('category',''))}</td><td>{_html_escape(m['text'])}</td><td>{m['span'][0]}..{m['span'][1]}</td></tr>")
                        report_parts.append("</table>")

                    # Show a preview with [REDACTED]
                    redacted = redact_text_content(text_content, compiled)
                    report_parts.append("<h3>Preview (first 1,000 chars)</h3>")
                    report_parts.append("<pre>" + _html_escape(redacted[:1000]) + ("..." if len(redacted) > 1000 else "") + "</pre>")

                elif ext in ['.pdf'] or (mime == 'application/pdf'):
                    if fitz is None:
                        report_parts.append("<p>PyMuPDF not available; cannot render PDF preview.</p>")
                    else:
                        doc = fitz.open(stream=file_data, filetype='pdf')
                        total = len(doc)
                        report_parts.append(f"<p>Pages: {total}</p>")
                        if total > 0:
                            page = doc[0]
                            # Decide method: text-layer or OCR fallback
                            method = 'text'
                            try:
                                page_text = page.get_text() or ''
                                if not page_text.strip():
                                    method = 'ocr'
                            except Exception:
                                method = 'ocr'

                            # Build detections
                            if method == 'text':
                                dets = find_pdf_matches(page, compiled)
                            else:
                                # For debug table, build detailed entries with OCR text via image detector
                                pix = page.get_pixmap()
                                import numpy as _np
                                oimg = _np.frombuffer(pix.samples, dtype=_np.uint8).reshape(pix.height, pix.width, pix.n)
                                oimg = oimg.copy()
                                if cv2 is not None and pix.n == 4:
                                    oimg = cv2.cvtColor(oimg, cv2.COLOR_RGBA2BGR)
                                elif cv2 is not None and pix.n == 3:
                                    oimg = cv2.cvtColor(oimg, cv2.COLOR_RGB2BGR)
                                dets_img = detect_image_matches(oimg, compiled, ocr_min_conf=ocr_min_conf)
                                # Map pixel bboxes to page coords
                                page_w = float(page.rect.width); page_h = float(page.rect.height)
                                sx = page_w / float(pix.width or 1); sy = page_h / float(pix.height or 1)
                                dets = []
                                for d in dets_img:
                                    x0,y0,x1,y1 = d['bbox']
                                    dets.append({
                                        'text': d.get('text',''),
                                        'bbox': (x0*sx, y0*sy, x1*sx, y1*sy),
                                        'match_type': d.get('match_type','ocr'),
                                        'category': d.get('category','')
                                    })

                            report_parts.append(f"<p>Page 1 method: <b>{'Text Layer' if method=='text' else 'OCR Fallback'}</b></p>")
                            report_parts.append(f"<p>Page 1 detections: <b>{len(dets)}</b></p>")
                            if dets:
                                report_parts.append("<table><tr><th>Type</th><th>Category</th><th>Text</th><th>BBox (x0,y0,x1,y1)</th></tr>")
                                for d in dets[:500]:
                                    x0,y0,x1,y1 = d['bbox']
                                    report_parts.append(f"<tr><td>{d['match_type']}</td><td>{_html_escape(d.get('category',''))}</td><td>{_html_escape(str(d.get('text','')))}</td><td>{x0:.1f},{y0:.1f},{x1:.1f},{y1:.1f}</td></tr>")
                                report_parts.append("</table>")

                            # Render page image and overlay boxes for preview
                            pix = page.get_pixmap()
                            import numpy as _np
                            img = _np.frombuffer(pix.samples, dtype=_np.uint8).reshape(pix.height, pix.width, pix.n)
                            img = img.copy()
                            if cv2 is not None and pix.n == 4:
                                img = cv2.cvtColor(img, cv2.COLOR_RGBA2BGR)
                            elif cv2 is not None and pix.n == 3:
                                img = cv2.cvtColor(img, cv2.COLOR_RGB2BGR)
                            # Draw rectangles (map page units -> pixel units)
                            page_w = float(page.rect.width); page_h = float(page.rect.height)
                            sx = float(pix.width or 1) / page_w; sy = float(pix.height or 1) / page_h
                            if cv2 is not None and len(dets) > 0:
                                for d in dets:
                                    x0,y0,x1,y1 = d['bbox']
                                    px0, py0, px1, py1 = int(x0 * sx), int(y0 * sy), int(x1 * sx), int(y1 * sy)
                                    cv2.rectangle(img, (px0,py0), (px1,py1), (0,0,0), thickness=2)
                            # Encode preview
                            if cv2 is not None:
                                ok, buf = cv2.imencode('.png', img)
                                preview = buf.tobytes() if ok else b''
                            else:
                                preview = pix.tobytes('png')
                            report_parts.append("<h3>Page 1 preview</h3>")
                            report_parts.append(f"<img src='{_img_bytes_to_data_url(preview, 'image/png')}' style='max-width:100%;height:auto'/>")
                            doc.close()

                elif ext in ['.png', '.jpg', '.jpeg'] or (mime and mime.startswith('image')):
                    if cv2 is None:
                        report_parts.append("<p>OpenCV not available; cannot render image preview.</p>")
                    else:
                        import numpy as _np
                        img = cv2.imdecode(_np.frombuffer(file_data, dtype=_np.uint8), cv2.IMREAD_COLOR)
                        dets = detect_image_matches(img, compiled, ocr_min_conf=ocr_min_conf)
                        report_parts.append(f"<p>Detections: <b>{len(dets)}</b></p>")
                        if dets:
                            report_parts.append("<table><tr><th>Type</th><th>Category</th><th>Text</th><th>Conf</th><th>BBox (x0,y0,x1,y1)</th></tr>")
                            for d in dets[:500]:
                                x0,y0,x1,y1 = d['bbox']
                                conf = d.get('conf', '')
                                report_parts.append(f"<tr><td>{d['match_type']}</td><td>{_html_escape(d.get('category',''))}</td><td>{_html_escape(str(d.get('text','')))}</td><td>{conf}</td><td>{x0},{y0},{x1},{y1}</td></tr>")
                            report_parts.append("</table>")
                        # Draw boxes for preview
                        if img is not None and dets:
                            for d in dets:
                                x0,y0,x1,y1 = map(int, d['bbox'])
                                cv2.rectangle(img, (x0,y0), (x1,y1), (0,0,0), thickness=2)
                        ok, buf = cv2.imencode('.png', img if img is not None else np.zeros((1,1,3), dtype=np.uint8))
                        preview = buf.tobytes() if ok else b''
                        report_parts.append("<h3>Image preview</h3>")
                        report_parts.append(f"<img src='{_img_bytes_to_data_url(preview, 'image/png')}' style='max-width:100%;height:auto'/>")

                else:
                    report_parts.append("<p>Unsupported file type for debug report.</p>")

                report_parts.append("</body></html>")
                html_report = "".join(report_parts)
                self.send_response(HTTPStatus.OK)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', str(len(html_report.encode('utf-8'))))
                self.end_headers()
                self.wfile.write(html_report.encode('utf-8'))
                return

            # Normal (non-debug) processing and download
            if ext in ['.txt', '.text'] or (mime and mime.startswith('text')):
                text_content = file_data.decode('utf-8', errors='ignore')
                redacted = redact_text_content(text_content, compiled)
                output_data = redacted.encode('utf-8')
                out_ext = '.txt'
            elif ext in ['.pdf'] or (mime == 'application/pdf'):
                output_data = redact_pdf(file_data, compiled)
                out_ext = '.pdf'
            elif ext in ['.png', '.jpg', '.jpeg'] or (mime and mime.startswith('image')):
                img_format = ext.lstrip('.') or 'png'
                output_data = redact_image(file_data, compiled, img_format, ocr_min_conf=ocr_min_conf)
                out_ext = '.' + img_format
            else:
                output_data = file_data
                out_ext = ext or ''
        except Exception as e:
            err_msg = f"Error during redaction: {e}"
            self.send_response(HTTPStatus.INTERNAL_SERVER_ERROR)
            self.send_header('Content-Type', 'text/plain; charset=utf-8')
            self.send_header('Content-Length', str(len(err_msg)))
            self.end_headers()
            self.wfile.write(err_msg.encode('utf-8'))
            return
        # Determine output filename
        base_name = os.path.splitext(filename)[0]
        out_name = f"{base_name}-redacted{out_ext}"
        # To avoid collisions, append timestamp
        timestamp = int(time.time()*1000)
        out_name = f"{base_name}-redacted-{timestamp}{out_ext}"
        # Send file as attachment
        self.send_response(HTTPStatus.OK)
        # Set appropriate content type for the redacted file
        if out_ext == '.pdf':
            content_type = 'application/pdf'
        elif out_ext in ['.txt', '.text']:
            content_type = 'text/plain; charset=utf-8'
        elif out_ext in ['.png', '.jpg', '.jpeg']:
            content_type = f"image/{out_ext.lstrip('.')}"
        else:
            content_type = 'application/octet-stream'
        self.send_header('Content-Type', content_type)
        self.send_header('Content-Disposition', f'attachment; filename="{out_name}"')
        self.send_header('Content-Length', str(len(output_data)))
        self.end_headers()
        self.wfile.write(output_data)




def run(server_class=HTTPServer, handler_class=RedactionHandler, port=8000):
    """Start the HTTP server, find a free port if needed, and open the browser."""
    # Try requested port, then the next 20 ports if busy
    bound_port = None
    httpd = None
    for candidate in [port] + list(range(port + 1, port + 21)):
        try:
            httpd = server_class(('127.0.0.1', candidate), handler_class)
            bound_port = candidate
            break
        except OSError:
            continue
    if httpd is None or bound_port is None:
        raise RuntimeError("Unable to bind an HTTP port.")

    url = f"http://127.0.0.1:{bound_port}"
    print(f"Redaction server starting on {url}")

    # Serve in a background thread so we can open the browser and keep UI responsive
    t = threading.Thread(target=httpd.serve_forever, daemon=True)
    t.start()

    # Wait until the port is actually accepting connections (max ~8s)
    for _ in range(32):
        try:
            with socket.create_connection(("127.0.0.1", bound_port), timeout=0.25):
                break
        except OSError:
            time.sleep(0.25)
    else:
        # Could not confirm listening, but continue anyway; user can open manually
        pass

    # Open the browser using robust strategy
    _open_url_robust(url)

    # Keep main thread alive until server shuts down
    try:
        while t.is_alive():
            time.sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        try:
            httpd.shutdown()
        except Exception:
            pass
        httpd.server_close()
        print("Server stopped")


if __name__ == '__main__':
    def get_port():
        # Priority: CLI arg > REDACTYL_PORT env var > PORT env var > default 8000
        if len(sys.argv) > 1:
            try:
                return int(sys.argv[1])
            except ValueError:
                print(f"Invalid port '{sys.argv[1]}', falling back to defaults")
        for key in ('REDACTYL_PORT', 'PORT'):
            val = os.environ.get(key)
            if val:
                try:
                    return int(val)
                except ValueError:
                    pass
        return 8000

    port = get_port()
    print(f"Requested port: {port}")
    run(port=port)