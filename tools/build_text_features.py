"""Precompute the CLIP text embeddings for the arbiter's fixed prompt lists.

The arbiter tokenizes + text-encodes its prompts exactly ONCE, at load(), and
never again -- so there's no reason to carry the CLIP text encoder
(clip_text.onnx, ~240MB) or a BPE tokenizer (transformers) in the resident
process for the whole run. This script does that one encode offline and writes
the result to eyeguard/clip_assets/text_features.npz, keyed by a hash of the
prompts + model id. detector.py loads that at runtime; a hash mismatch (someone
edited the prompts in config.yaml without regenerating) makes the arbiter
unavailable with a loud load_error rather than scoring against stale concepts.

Run on a dev machine that still has transformers installed:
    python tools/build_text_features.py            # uses config.yaml
Commit the regenerated eyeguard/clip_assets/text_features.npz alongside any
prompt change.
"""
import hashlib
import json
import sys
from pathlib import Path

import numpy as np
import onnxruntime as ort
import yaml
from transformers import CLIPProcessor

ROOT = Path(__file__).resolve().parent.parent
MODEL_ID = "openai/clip-vit-base-patch32"
OUT = ROOT / "eyeguard" / "clip_assets" / "text_features.npz"


def prompts_hash(explicit, suggestive, safe, model_id):
    blob = json.dumps({"e": explicit, "s": suggestive, "f": safe, "m": model_id},
                      sort_keys=True, ensure_ascii=False)
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def main():
    cfg_path = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "config.yaml"
    cfg = yaml.safe_load(cfg_path.read_text())
    a = cfg["arbiter"]
    explicit = list(a["explicit_prompts"])
    suggestive = list(a["suggestive_prompts"])
    safe = list(a["safe_prompts"])
    ordered = explicit + suggestive + safe

    proc = CLIPProcessor.from_pretrained(MODEL_ID)
    txt = ort.InferenceSession(str(ROOT / "models" / "clip_text.onnx"),
                               providers=["CPUExecutionProvider"])
    tok = proc(text=ordered, return_tensors="np",
               padding="max_length", max_length=77)
    tf = txt.run(None, {"input_ids": tok["input_ids"].astype("int64"),
                        "attention_mask": tok["attention_mask"].astype("int64")})[0]
    feats = (tf / np.linalg.norm(tf, axis=-1, keepdims=True)).astype(np.float32)

    OUT.parent.mkdir(parents=True, exist_ok=True)
    np.savez(OUT,
             features=feats,
             hash=prompts_hash(explicit, suggestive, safe, MODEL_ID),
             n_explicit=len(explicit), n_suggestive=len(suggestive),
             n_safe=len(safe), model_id=MODEL_ID)
    print(f"wrote {OUT}  features={feats.shape}  "
          f"({len(explicit)}R/{len(suggestive)}Y/{len(safe)}safe)")


if __name__ == "__main__":
    main()
