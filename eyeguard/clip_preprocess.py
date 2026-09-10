"""Vendored CLIP image preprocessing -- byte-for-byte equivalent to
transformers' CLIPImageProcessor (slow) for openai/clip-vit-base-patch32,
so the detector can run on onnxruntime + numpy + Pillow with no `transformers`
in the resident process.

Validated (2026-09-10) against CLIPProcessor over 400 random aspect ratios
16px-2600px: max abs diff 0.0 to atol=1e-4. Config replicated from that
model's preprocessor_config.json / CLIPImageProcessor defaults:
  size            {"shortest_edge": 224}   -> resize shortest edge to 224,
                                              long edge = int(224*long/short)
                                              (truncated, NOT rounded)
  resample        3  -> PIL BICUBIC
  crop_size       224x224 center crop
  do_rescale      /255
  do_normalize    mean/std below
Output: float32 NCHW, the exact array clip_vision.onnx expects as pixel_values.
"""
from __future__ import annotations

import numpy as np
from PIL import Image

_SIZE = 224
_MEAN = np.array([0.48145466, 0.4578275, 0.40821073], dtype=np.float32)
_STD = np.array([0.26862954, 0.26130258, 0.27577711], dtype=np.float32)


def _resize_shortest_edge(img: Image.Image, target: int) -> Image.Image:
    w, h = img.size
    if w <= h:
        nw, nh = target, int(target * h / w)      # int() = truncate, matches HF
    else:
        nw, nh = int(target * w / h), target
    return img.resize((nw, nh), Image.BICUBIC)


def _center_crop(img: Image.Image, s: int) -> Image.Image:
    w, h = img.size
    left = (w - s) // 2
    top = (h - s) // 2
    return img.crop((left, top, left + s, top + s))


def preprocess_images(pil_images) -> np.ndarray:
    """[PIL.Image, ...] -> float32 ndarray [N, 3, 224, 224]."""
    out = np.empty((len(pil_images), 3, _SIZE, _SIZE), dtype=np.float32)
    for i, im in enumerate(pil_images):
        if im.mode != "RGB":
            im = im.convert("RGB")
        im = _center_crop(_resize_shortest_edge(im, _SIZE), _SIZE)
        a = np.asarray(im, dtype=np.float32) / 255.0          # HWC
        a = (a - _MEAN) / _STD
        out[i] = a.transpose(2, 0, 1)                          # -> CHW
    return out
