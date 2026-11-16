"""On-screen text + browsing-signal analysis.

EyeGuard's image detector is blind to the TEXTUAL side of behavior — erotic
text, sexual chat, explicit search terms — because there's no nude *image* to
classify. This adds two cheap, on-device checks that close that gap:

  * OCR the captured frame (Apple's Vision framework, local, no network) and
    flag when enough explicit terms appear.
  * Match explicit terms in the active URL / window title (search queries show
    up there), flagging the site as a signal in its own right.

Word-boundary matching avoids false hits like "sex" inside "Middlesex".
"""

from __future__ import annotations

import contextlib
import io
import re


def ocr(pil_image) -> str:
    """Recognize on-screen text via Apple Vision (on-device). '' on any failure.

    Runs inside an autorelease pool. The agent calls this from a plain Python thread, where nothing
    drains the Objective-C autorelease pool, so every call leaked ~0.6 MB of Vision/NSData objects
    (measured 2026-11-16: 300 calls = +250 MB without a pool, flat at ~95 MB with one). At one OCR
    every 8 s while video is changing that is ~250 MB/h, and it is what kept tripping the 1200 MB
    memory guard. The returned text is plain Python str, so it is safe to return after the pool drains."""
    try:
        import objc
        pool = objc.autorelease_pool
    except Exception:           # no PyObjC (non-macOS / tests): same behaviour as before
        pool = contextlib.nullcontext
    with pool():
        return _ocr(pil_image)


def _ocr(pil_image) -> str:
    try:
        import Vision
        import Foundation
        buf = io.BytesIO()
        pil_image.save(buf, "PNG")
        raw = buf.getvalue()
        data = Foundation.NSData.dataWithBytes_length_(raw, len(raw))
        handler = Vision.VNImageRequestHandler.alloc().initWithData_options_(
            data, None)
        req = Vision.VNRecognizeTextRequest.alloc().init()
        req.setRecognitionLevel_(1)         # 1 = fast (plenty for screen text)
        req.setUsesLanguageCorrection_(False)
        handler.performRequests_error_([req], None)
        lines = []
        for obs in (req.results() or []):
            cand = obs.topCandidates_(1)
            if cand:
                lines.append(str(cand[0].string()))
        return "\n".join(lines)
    except Exception:
        return ""


def match_terms(text: str, terms: list[str]) -> list[str]:
    """Distinct explicit terms present in `text`, matched on word boundaries."""
    if not text:
        return []
    low = text.lower()
    hits = []
    for t in terms:
        t = str(t).lower()
        if re.search(r"\b" + re.escape(t) + r"\b", low):
            hits.append(t)
    return hits
