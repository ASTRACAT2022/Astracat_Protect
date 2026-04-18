#!/usr/bin/env python3
import json
import math
import os
import sys


def fallback_score(features: dict) -> float:
    suspicious = float(features.get("suspicious_hits", 0.0))
    path_len = float(features.get("path_length", 0.0))
    query_len = float(features.get("query_length", 0.0))
    body_len = float(features.get("body_length", 0.0))
    header_count = float(features.get("header_count", 0.0))
    query_params = float(features.get("query_params", 0.0))

    score = suspicious * 2.0
    score += min(path_len / 128.0, 2.0)
    score += min(query_len / 256.0, 1.5)
    score += min(body_len / 2048.0, 2.0)
    score += min(header_count / 40.0, 1.0)
    score += min(query_params / 20.0, 1.0)
    return max(0.0, min(10.0, score))


def run_tflite(model_path: str, features: dict) -> float:
    try:
        import numpy as np
    except Exception:
        return fallback_score(features)

    try:
        from tflite_runtime.interpreter import Interpreter
    except Exception:
        try:
            from tensorflow.lite import Interpreter
        except Exception:
            return fallback_score(features)

    if not model_path or not os.path.exists(model_path):
        return fallback_score(features)

    x = [
        float(features.get("path_length", 0.0)),
        float(features.get("query_length", 0.0)),
        float(features.get("header_count", 0.0)),
        float(features.get("query_params", 0.0)),
        float(features.get("body_length", 0.0)),
        float(features.get("suspicious_hits", 0.0)),
    ]
    tensor = np.array([x], dtype=np.float32)

    interpreter = Interpreter(model_path=model_path)
    interpreter.allocate_tensors()
    input_details = interpreter.get_input_details()
    output_details = interpreter.get_output_details()

    interpreter.set_tensor(input_details[0]["index"], tensor)
    interpreter.invoke()
    out = interpreter.get_tensor(output_details[0]["index"])

    try:
        raw = float(out[0][0])
    except Exception:
        raw = float(out[0]) if len(out) > 0 else 0.0

    if math.isnan(raw) or math.isinf(raw):
        return fallback_score(features)
    return max(0.0, min(10.0, raw))


def main() -> int:
    raw = sys.stdin.read().strip()
    if not raw:
        print(json.dumps({"score": 0.0, "reason": "empty-input"}))
        return 0

    data = json.loads(raw)
    model_path = data.get("model", "")
    features = data.get("features", {}) or {}

    score = run_tflite(model_path, features)
    result = {
        "score": score,
        "reason": "tflite-hook",
    }
    print(json.dumps(result, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
