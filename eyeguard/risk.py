"""Context-aware risk layer (no AI — just rules).

A CLIP flag's likelihood of being REAL depends on two things we already have:
  1. the detection confidence (CLIP's score), and
  2. *where* it happened (the app / window title / URL).

A flag on a terminal, a code editor, or a gameplay video is almost certainly
noise; the same flag on social media is worth surfacing. This module combines
the two to decide whether to keep a flag and to grade how likely it is real —
so we can keep detection sensitive without flooding on safe contexts.
"""

from __future__ import annotations

import re


def score_from_reason(reason: str | None) -> float:
    """Pull the confidence out of a detection reason string."""
    if not reason:
        return 1.0
    m = re.search(r"clip-(?:red|yellow):([0-9.]+)", reason)
    if m:
        return float(m.group(1))
    m = re.search(r"=([0-9.]+)", reason)  # nudenet "label=0.87"
    return float(m.group(1)) if m else 1.0


def pattern_hits(pat: str, ctx: dict, hay: str) -> bool:
    """One list entry vs one context. 'app:Name' matches only when the frontmost APP NAME is exactly
    Name (case-insensitive), so a word in a page title or URL ("promo code", "striped", "barcode")
    can never trigger it. Any other entry is a case-insensitive substring of app + title + url, as
    before. Used by the suppress / low_risk / high_risk lists and by the ignore list."""
    p = str(pat).strip()
    if p.lower().startswith("app:"):
        return (ctx.get("app") or "").strip().lower() == p[4:].strip().lower()
    return p.lower() in hay


def _haystack(ctx: dict) -> str:
    return " ".join(filter(None, [ctx.get("app"), ctx.get("window_title"),
                                  ctx.get("url")])).lower()


def assess(verdict: str, reason: str, ctx: dict, rules: dict) -> dict:
    """Decide keep/drop + a confidence grade for one flag.

    Returns {keep, risk, grade, score}. `verdict` is "flagged" (RED) or "alert".
    Rules (all optional, case-insensitive substring lists):
      suppress           — drop ALL flags from these contexts (safe apps/sites)
      low_risk           — drop YELLOW unless very confident (e.g. gameplay)
      high_risk          — real-risk contexts: keep + grade up (social media)
      red_always_through — if true, RED is never suppressed (default true)
    """
    hay = _haystack(ctx)
    score = score_from_reason(reason)
    is_red = verdict == "flagged"

    def hit(key):
        return any(pattern_hits(p, ctx, hay) for p in rules.get(key, []))

    # SUPPRESS contexts (terminal, code editors, Claude, login...) cannot contain
    # real flaggable content, so drop EVERYTHING here — including RED. This is
    # where text-heavy dark screens get misread as nudity. RED still always
    # surfaces on every OTHER context (low_risk like Photos, neutral, high_risk),
    # so genuine nudity is never hidden where it could actually appear.
    if hit("suppress"):
        return {"keep": False, "risk": "suppressed", "grade": "", "score": score}

    if hit("high_risk"):
        risk = "high"
    elif hit("low_risk"):
        risk = "low"
    else:
        risk = "neutral"

    # Low-risk context (YouTube gaming/nature, Photos, etc.): require high
    # confidence to keep. YELLOW at low_risk_min_confidence; a CLIP RED needs an
    # even higher bar (low_risk_red_min_confidence) because game/nature textures
    # misread as nudity at 0.7-0.9 here. NudeNet reds (a trained detector actually
    # found exposure) are NEVER discounted — genuine nudity still surfaces.
    if risk == "low":
        is_nudenet = (reason or "").startswith("nudenet")
        if is_red and not is_nudenet:
            red_min = float(rules.get("low_risk_red_min_confidence", 0.93))
            if score < red_min:
                # A CLIP RED too weak for the low-risk RED bar is NOT dropped when it is still a
                # confident yellow: report it as YELLOW (its red probability is part of the
                # yellow mass, so score >= low_risk_min_confidence means yellow clears its bar).
                # Before 2026-10-21 it was dropped, so the most severe detections vanished
                # while milder ones survived.
                if rules.get("low_risk_red_demote", True) and score >= float(rules.get("low_risk_min_confidence", 0.85)):
                    return {"keep": True, "risk": risk, "grade": "Likely" if score >= 0.85 else "Possible",
                            "score": round(score, 3), "demote_to_alert": True}
                return {"keep": False, "risk": "low-discarded", "grade": "",
                        "score": score}
        elif not is_red:
            min_conf = float(rules.get("low_risk_min_confidence", 0.85))
            if score < min_conf:
                return {"keep": False, "risk": "low-discarded", "grade": "",
                        "score": score}

    # Grade: confidence nudged up on high-risk contexts.
    eff = score + (0.10 if risk == "high" else 0.0)
    if is_red or eff >= 0.85:
        grade = "Likely"
    elif eff >= 0.68:
        grade = "Possible"
    else:
        grade = "Borderline"
    return {"keep": True, "risk": risk, "grade": grade, "score": round(score, 3)}
