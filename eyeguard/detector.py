"""Tiered content detection.

Stage 1 (fast short-circuit): NudeNet, an on-CPU NSFW detector. If it sees actual
exposure at high confidence the frame is FLAGGED immediately, skipping Stage 2.

Stage 2 (the real judge): a CLIP zero-shot arbiter runs on every non-explicit
frame and decides RED (explicit) / YELLOW (suggestive) / SAFE by a head-to-head
between the best explicit, suggestive, and safe text concepts.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path

import numpy as np
from PIL import Image


class Verdict(str, Enum):
    SAFE = "safe"
    REVIEW = "review"    # borderline, arbiter unavailable / inconclusive
    ALERT = "alert"      # YELLOW tier: suggestive but not explicit
    FLAGGED = "flagged"  # RED tier: nude / explicit / exposed


@dataclass
class Detection:
    verdict: Verdict
    reason: str
    top_score: float = 0.0
    labels: dict[str, float] = field(default_factory=dict)
    arbiter_answer: str | None = None


class NudeNetStage:
    """Stage 1: fast explicit-exposure short-circuit.

    Runs NudeNet and FLAGs the frame only when an `explicit_labels` region (actual
    exposure) scores >= flag_threshold — a cheap way to catch obvious nudity
    without the heavier CLIP pass. Everything else returns SAFE and is handed to
    the CLIP arbiter, which makes the real call on suggestive/borderline content.
    """

    def __init__(self, explicit_labels: list[str], flag_threshold: float):
        self.explicit_labels = set(explicit_labels)
        self.flag_threshold = flag_threshold
        self._detector = None

    def _ensure_loaded(self):
        if self._detector is None:
            from nudenet import NudeDetector
            self._detector = NudeDetector()

    def _raw_detect(self, image: Image.Image) -> list[dict]:
        self._ensure_loaded()
        # NudeNet wants BGR (OpenCV order). Pass an ndarray to avoid disk I/O.
        arr = np.asarray(image.convert("RGB"))[:, :, ::-1]
        try:
            return self._detector.detect(arr)
        except (TypeError, AttributeError):
            # Older NudeNet builds only accept a path — fall back to a temp file.
            import tempfile, os
            fd, path = tempfile.mkstemp(suffix=".jpg")
            os.close(fd)
            try:
                image.convert("RGB").save(path, "JPEG", quality=85)
                return self._detector.detect(path)
            finally:
                os.unlink(path)

    def detect(self, image: Image.Image) -> Detection:
        regions = self._raw_detect(image)
        explicit: dict[str, float] = {}
        for r in regions:
            label = r.get("class", r.get("label", ""))
            score = float(r.get("score", 0.0))
            if label in self.explicit_labels:
                explicit[label] = max(explicit.get(label, 0.0), score)

        top = max(explicit.values(), default=0.0)
        if top >= self.flag_threshold:
            worst = max(explicit, key=explicit.get)
            return Detection(Verdict.FLAGGED, f"nudenet:{worst}={top:.2f}",
                             top_score=top, labels=explicit)
        return Detection(Verdict.SAFE, "clear", top_score=top, labels=explicit)


class ClipArbiter:
    """Stage 2: CLIP zero-shot concept scorer.

    Lightweight alternative to a generative VLM — fits an 8GB machine (~0.5GB,
    ~150ms/frame at the configured tiling). Embeds the frame (and overlapping
    tiles) and scores three concept groups head-to-head: `explicit_prompts` (RED),
    `suggestive_prompts` (YELLOW), and `safe_prompts`. Each group is represented
    by its single best-matching prompt; those three are softmaxed against each
    other, so a flag only wins when it beats the best SAFE concept for that image.

    All inference is local: clip_vision.onnx runs on onnxruntime, prompt
    embeddings are precomputed (clip_assets/text_features.npz), image
    preprocessing is vendored (clip_preprocess.py). If the model or asset is
    missing / stale, `available` stays False and the pipeline fails open
    (frames recorded as "review", not flagged).
    """

    DEFAULT_MODEL_ID = "openai/clip-vit-base-patch32"

    def __init__(self, explicit_prompts: list[str], suggestive_prompts: list[str],
                 safe_prompts: list[str], red_threshold: float = 0.40,
                 yellow_threshold: float = 0.30, model_id: str | None = None,
                 tile_grid: int = 1, tile_penalty: float = 0.12,
                 min_content_std: float = 12.0):
        # Two tiers: explicit_prompts -> RED (FLAGGED), suggestive_prompts ->
        # YELLOW (ALERT). safe_prompts give CLIP neutral concepts to prefer.
        self.explicit_prompts = explicit_prompts
        self.suggestive_prompts = suggestive_prompts
        self.safe_prompts = safe_prompts
        self.red_threshold = red_threshold
        self.yellow_threshold = yellow_threshold
        self.model_id = model_id or self.DEFAULT_MODEL_ID
        # tile_grid > 1 splits each frame into an NxN grid of overlapping tiles
        # (plus the full frame) so small on-screen windows aren't drowned out by
        # the surrounding desktop. Each tile is scored independently; the frame
        # takes the most severe tier any tile reaches.
        self.tile_grid = max(1, tile_grid)
        # Tiles are zoomed and noisier than the full frame, so they must clear a
        # HIGHER bar to flag (threshold + tile_penalty). This stops a single tile
        # that zoomed into a clothed torso from turning the whole frame red.
        self.tile_penalty = tile_penalty
        # Min grayscale std for a crop to be considered "has content" worth
        # scoring. Below this = blank/uniform -> never flags.
        self.min_content_std = min_content_std
        self._text_features = None
        self._preprocess_images = None
        self._n_red = len(explicit_prompts)
        self._n_yellow = len(suggestive_prompts)
        self.available = False
        self.load_error: str | None = None

    def load(self):
        try:
            import hashlib
            import json
            import onnxruntime as ort
            from .clip_preprocess import preprocess_images
            self._preprocess_images = preprocess_images
            model_dir = Path(__file__).resolve().parent.parent / "models"
            so = ort.SessionOptions()
            so.intra_op_num_threads = 2          # modest CPU/RAM
            # Captures are periodic (~15-20s apart), not a stream -- there is no
            # benefit to ORT holding a pre-grown CPU arena or a whole-graph
            # activation-memory plan resident between inferences. Both off =
            # allocate per run, free after; numerically identical output, a
            # few ms slower per call, materially smaller steady-state
            # MALLOC_LARGE footprint (2026-09-10 profiling: MALLOC_LARGE was
            # ~1.7G logical of a 1.71G phys_footprint).
            so.enable_cpu_mem_arena = False
            so.enable_mem_pattern = False
            providers = ["CPUExecutionProvider"]
            self._vis = ort.InferenceSession(str(model_dir / "clip_vision.onnx"),
                                             sess_options=so, providers=providers)
            self._logit_scale = float(json.loads(
                (model_dir / "clip_meta.json").read_text())["logit_scale"])
            # Prompt embeddings are precomputed offline (tools/build_text_
            # features.py) and shipped as a committed asset -- the CLIP text
            # encoder (clip_text.onnx, ~240MB) and a BPE tokenizer
            # (transformers) are only ever needed for this one-time encode, so
            # neither is loaded in the resident process anymore (2026-09-10).
            # A prompts/model-id hash guards against the asset going stale:
            # edit the prompts in config.yaml without regenerating and the
            # arbiter goes unavailable with a loud error rather than scoring
            # against the wrong concepts.
            blob = json.dumps({"e": list(self.explicit_prompts),
                               "s": list(self.suggestive_prompts),
                               "f": list(self.safe_prompts),
                               "m": self.model_id},
                              sort_keys=True, ensure_ascii=False)
            want = hashlib.sha256(blob.encode("utf-8")).hexdigest()
            asset = (Path(__file__).resolve().parent
                     / "clip_assets" / "text_features.npz")
            data = np.load(asset)
            if str(data["hash"]) != want:
                raise RuntimeError(
                    "clip_assets/text_features.npz is stale for the current "
                    "arbiter prompts -- regenerate with "
                    "tools/build_text_features.py and commit it")
            if (int(data["n_explicit"]) != self._n_red
                    or int(data["n_suggestive"]) != self._n_yellow):
                raise RuntimeError("text_features.npz tier counts disagree with "
                                   "the configured prompt lists")
            self._text_features = data["features"].astype(np.float32)
            self.available = True
        except Exception as e:
            self.available = False
            self.load_error = f"{type(e).__name__}: {e}"

    def _crops(self, image: Image.Image) -> list[Image.Image]:
        """Full frame + an NxN grid of overlapping tiles."""
        crops = [image]
        n = self.tile_grid
        if n <= 1:
            return crops
        W, H = image.size
        # Tiles ~1.5/n of each dimension so adjacent tiles overlap ~50% — keeps a
        # subject from being split across a tile boundary and missed.
        tw = min(W, int(round(W * 1.5 / n)))
        th = min(H, int(round(H * 1.5 / n)))
        xs = np.linspace(0, W - tw, n).round().astype(int)
        ys = np.linspace(0, H - th, n).round().astype(int)
        for y in ys:
            for x in xs:
                crops.append(image.crop((int(x), int(y), int(x) + tw,
                                         int(y) + th)))
        return crops

    def arbitrate(self, image: Image.Image) -> tuple[Verdict, str]:
        if not self.available:
            return Verdict.REVIEW, "arbiter-unavailable"
        try:
            crops = [c.convert("RGB") for c in self._crops(image)]
            r, y = self._n_red, self._n_yellow

            # Content gate: a near-blank / uniform crop (blank screen, solid
            # background, empty page) has nothing to flag, but CLIP's head-to-head
            # still picks *some* winner — often a suggestive prompt on empty
            # pixels. Skip crops whose grayscale std is below min_content_std; if
            # every crop is blank, the frame is SAFE outright.
            stds = np.array([
                float(np.asarray(c.convert("L"), dtype=np.float32).std())
                for c in crops])
            content_mask = stds >= self.min_content_std
            if not content_mask.any():
                return Verdict.SAFE, f"blank(std={stds.max():.0f})"

            pix = self._preprocess_images(crops)
            img_f = self._vis.run(None, {"pixel_values": pix})[0]
            img_f = img_f / np.linalg.norm(img_f, axis=-1, keepdims=True)
            # Cosine sims (both already L2-normalized) in [-1, 1].
            sims = img_f @ self._text_features.T            # [n_crops, n_prompts]
            # Head-to-head: each tier represented by its SINGLE best prompt, then
            # softmax those 3 against each other (hub-resistant, size-invariant).
            s_red = sims[:, :r].max(axis=1)                  # best explicit
            s_yel = sims[:, r:r + y].max(axis=1)             # best suggestive
            s_safe = sims[:, r + y:].max(axis=1)             # best safe
            group = np.stack([s_red, s_yel, s_safe], axis=1) * self._logit_scale
            e = np.exp(group - group.max(axis=1, keepdims=True))
            gp = e / e.sum(axis=1, keepdims=True)            # [n_crops, 3]
            red_per_crop = np.where(content_mask, gp[:, 0], 0.0)
            combined = np.where(content_mask, gp[:, 0] + gp[:, 1], 0.0)
            probs = sims  # reused below only to pick the reporting prompt
            n_crops = sims.shape[0]

            # Per-crop thresholds: full frame (idx 0) at base, tiles higher.
            red_thr = np.full(n_crops, self.red_threshold)
            yel_thr = np.full(n_crops, self.yellow_threshold)
            if n_crops > 1:
                red_thr[1:] += self.tile_penalty
                yel_thr[1:] += self.tile_penalty

            red_hit, red_crop, red_mass = self._tier_hit(red_per_crop, red_thr)
            yel_hit, yel_crop, yel_mass = self._tier_hit(combined, yel_thr)
        except Exception as e:
            return Verdict.REVIEW, f"arbiter-error:{type(e).__name__}"

        if red_hit:
            best = int(probs[red_crop, :r].argmax())
            where = "full" if red_crop == 0 else f"tile{red_crop}"
            return Verdict.FLAGGED, \
                f"clip-red:{red_mass:.2f}:{where}:{self.explicit_prompts[best][:24]}"
        if yel_hit:
            best = int(probs[yel_crop, r:r + y].argmax())
            where = "full" if yel_crop == 0 else f"tile{yel_crop}"
            return Verdict.ALERT, \
                f"clip-yellow:{yel_mass:.2f}:{where}:{self.suggestive_prompts[best][:24]}"
        return Verdict.SAFE, f"clip:r{red_mass:.2f}/y{yel_mass:.2f}"

    @staticmethod
    def _tier_hit(mass_per_crop, thr_per_crop):
        """Return (hit, crop_idx, mass). A hit needs a crop whose mass clears its
        own threshold; report the highest-mass crop that did. If none clear,
        report the highest-mass crop anyway (for the SAFE reason string)."""
        exceed = mass_per_crop >= thr_per_crop
        if bool(exceed.any()):
            masked = np.where(exceed, mass_per_crop, -1.0)
            idx = int(masked.argmax())
            return True, idx, float(mass_per_crop[idx])
        idx = int(mass_per_crop.argmax())
        return False, idx, float(mass_per_crop[idx])


class Detector:
    """Orchestrates Stage 1 -> Stage 2."""

    def __init__(self, stage1: NudeNetStage, arbiter: "ClipArbiter | None"):
        self.stage1 = stage1
        self.arbiter = arbiter

    def analyze(self, image: Image.Image) -> Detection:
        result = self.stage1.detect(image)
        # Explicit exposure short-circuits straight to a flag.
        if result.verdict is Verdict.FLAGGED:
            return result
        # Otherwise let CLIP judge EVERY frame directly (it's cheap). NudeNet no
        # longer gates it — that gating was causing missed gym-clothes / gestures
        # / clothed-but-revealing frames NudeNet didn't register as body regions.
        if self.arbiter is not None:
            verdict, reason = self.arbiter.arbitrate(image)
            result.verdict = verdict
            result.arbiter_answer = reason
            result.reason = (f"{result.reason} -> {reason}"
                             if result.verdict is not Verdict.SAFE
                             else reason)
        return result
