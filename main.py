"""
XDR Malware Detection Platform — Backend v1.2
Layer 0: Hash reputation (VirusTotal mock)
Layer 1: Static analysis — single model OR 5-model ensemble voting
          Models: VGG16, ResNet50, InceptionV3, Autoencoder, Basic CNN
"""

import hashlib
import time
import numpy as np
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, File, UploadFile, HTTPException, Form
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

# ── optional heavy deps ──────────────────────────────────────────────────────
try:
    import tensorflow as tf
    TF_AVAILABLE = True
except ImportError:
    TF_AVAILABLE = False

try:
    from PIL import Image
    PIL_AVAILABLE = True
except ImportError:
    PIL_AVAILABLE = False

# ─────────────────────────────────────────────────────────────────────────────
app = FastAPI(title="XDR Malware Detection API", version="1.3.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["*"],
    allow_headers=["*"],
)

UPLOAD_DIR = Path("uploads")
UPLOAD_DIR.mkdir(exist_ok=True)
MODEL_DIR = Path("models")
MODEL_DIR.mkdir(exist_ok=True)

# ── model cache ───────────────────────────────────────────────────────────────
_loaded_models: dict = {}

# 5 models — odd number guarantees no 50/50 splits
MODEL_OPTIONS = ["vgg16", "resnet50", "inceptionv3", "autoencoder", "basic_cnn"]
ENSEMBLE_NAME = "ensemble"

# Weights = paper-reported accuracy on Trapmine test set
MODEL_WEIGHTS = {
    "vgg16":       0.9125,
    "resnet50":    0.9111,
    "inceptionv3": 0.9041,
    "autoencoder": 0.9056,
    "basic_cnn":   0.8005,
}

# ─────────────────────────────────────────────────────────────────────────────
# LAYER 0 — Hash Reputation (VirusTotal mock)
#
# To switch to real VirusTotal, replace mock_virustotal_lookup() with:
#
#   import requests
#   VIRUSTOTAL_API_KEY = "YOUR_KEY_HERE"
#
#   def real_virustotal_lookup(sha256: str) -> dict:
#       r = requests.get(
#           f"https://www.virustotal.com/api/v3/files/{sha256}",
#           headers={"x-apikey": VIRUSTOTAL_API_KEY}
#       )
#       if r.status_code == 200:
#           stats = r.json()["data"]["attributes"]["last_analysis_stats"]
#           mal   = stats.get("malicious", 0)
#           total = sum(stats.values())
#           return {
#               "known": True, "sha256": sha256,
#               "malicious_engines": mal, "total_engines": total,
#               "verdict": "malicious" if mal > 5 else "benign",
#               "confidence": round(mal / total, 3),
#               "source": "VirusTotal"
#           }
#       return {"known": False, "sha256": sha256, "verdict": "unknown",
#               "confidence": 0, "source": "VirusTotal"}
#
# Then replace mock_virustotal_lookup(sha256) call with real_virustotal_lookup(sha256)
# ─────────────────────────────────────────────────────────────────────────────

MOCK_KNOWN_HASHES = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855": (0,  72),
    "deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef": (68, 72),
}

def mock_virustotal_lookup(sha256: str) -> dict:
    time.sleep(0.3)
    if sha256 in MOCK_KNOWN_HASHES:
        mal, total = MOCK_KNOWN_HASHES[sha256]
        verdict = "malicious" if mal > 5 else "benign"
        return {
            "known": True, "sha256": sha256,
            "malicious_engines": mal, "total_engines": total,
            "verdict": verdict,
            "confidence": round(mal / total, 3) if total else 0,
            "source": "VirusTotal (mock)"
        }
    return {
        "known": False, "sha256": sha256,
        "verdict": "unknown", "confidence": 0,
        "source": "VirusTotal (mock)"
    }


# ─────────────────────────────────────────────────────────────────────────────
# LAYER 1 — PE to RGB Image
# Exact logic from Paper_Tests.ipynb (rgb_image_convert function)
# ─────────────────────────────────────────────────────────────────────────────

def pe_to_rgb_image(file_bytes: bytes, target_size: int = 224) -> Optional[np.ndarray]:
    """
    Convert PE binary to 224x224 RGB image.
    Matches rgb_image_convert() in Paper_Tests.ipynb exactly:
        width = int(sqrt(n_pixels)) + 1
        Image.new + putdata
        resize bilinear to 224x224
        normalise /255
    """
    if not PIL_AVAILABLE:
        return None

    binary = list(file_bytes)
    ind, rgb_im = 0, []
    while (ind + 3) < len(binary):
        rgb_im.append((binary[ind], binary[ind + 1], binary[ind + 2]))
        ind += 3

    if not rgb_im:
        return None

    width = height = int(np.sqrt(len(rgb_im))) + 1
    image = Image.new('RGB', (width, height))
    image.putdata(rgb_im)
    image = image.resize((target_size, target_size), Image.BILINEAR)
    return np.array(image).astype(np.float32) / 255.0


# ─────────────────────────────────────────────────────────────────────────────
# MODEL LOADING & INFERENCE
# ─────────────────────────────────────────────────────────────────────────────

def load_model(model_name: str):
    """Load and cache a .h5 model. Returns None if file not found."""
    if model_name in _loaded_models:
        return _loaded_models[model_name]
    if not TF_AVAILABLE:
        return None
    # inceptionv3 için .keras formatı kullan
    if model_name == "inceptionv3":
        path = MODEL_DIR / "inceptionv3_v2.keras"
    else:
        path = MODEL_DIR / f"{model_name}.h5"
    if not path.exists():
        return None
    print(f"[XDR] Loading model: {model_name}.h5 ...")
    m = tf.keras.models.load_model(str(path))
    _loaded_models[model_name] = m
    print(f"[XDR] Model loaded: {model_name}")
    return m


def predict_single(img_array: np.ndarray, model_name: str) -> dict:
    """
    Run one model on a 224x224x3 float32 image normalised to [0,1].

    Matches notebook training setup:
        class_mode = 'binary'
        alphabetical label order → 0 = benign, 1 = malicious
        sigmoid output → P(malicious)
        threshold = 0.5
    """
    model = load_model(model_name)

    if model is None:
        # Demo mode — no .h5 file found
        import random
        score = round(random.uniform(0.05, 0.95), 4)
        return {
            "score":      score,
            "verdict":    "malicious" if score > 0.5 else "benign",
            "confidence": round(abs(score - 0.5) * 2, 3),
            "model_used": model_name,
            "mode":       "demo (no .h5 found)"
        }

    raw   = model.predict(np.expand_dims(img_array, 0), verbose=0)
    # sigmoid → (1,1)  or  softmax → (1,2)
    score = float(raw[0][0]) if raw.shape[-1] == 1 else float(raw[0][1])

    return {
        "score":      round(score, 4),
        "verdict":    "malicious" if score > 0.5 else "benign",
        "confidence": round(abs(score - 0.5) * 2, 3),
        "model_used": model_name,
        "mode":       "inference"
    }


def run_ensemble(img_array: np.ndarray) -> dict:
    """
    Weighted majority vote across all 5 models.

    Weights = paper-reported accuracy:
        VGG16 0.9125 | ResNet50 0.9111 | InceptionV3 0.9041
        Autoencoder 0.9056 | BasicCNN 0.8005

    Weighted score = Σ(weight_i × score_i) / Σ(weights)
    Final verdict  = malicious if weighted_score > 0.5

    With 5 models (odd), split is always at least 3 vs 2:
        5/5 → UNANIMOUS     (HIGH confidence)
        4/5 → STRONG        (HIGH confidence)
        3/5 → MAJORITY      (MEDIUM confidence)
    """
    individual = {name: predict_single(img_array, name) for name in MODEL_OPTIONS}

    total_weight   = sum(MODEL_WEIGHTS.values())
    weighted_score = sum(
        MODEL_WEIGHTS[n] * individual[n]["score"] for n in MODEL_OPTIONS
    ) / total_weight

    final_verdict   = "malicious" if weighted_score > 0.5 else "benign"
    votes_malicious = sum(1 for n in MODEL_OPTIONS if individual[n]["verdict"] == "malicious")
    votes_benign    = len(MODEL_OPTIONS) - votes_malicious
    agreeing        = votes_malicious if final_verdict == "malicious" else votes_benign
    total_models    = len(MODEL_OPTIONS)
    agreement_pct   = agreeing / total_models

    if agreeing == total_models:
        agreement_label, conf_level = f"UNANIMOUS ({total_models}/{total_models})", "HIGH"
    elif agreeing == total_models - 1:
        agreement_label, conf_level = f"STRONG ({agreeing}/{total_models})", "HIGH"
    else:
        agreement_label, conf_level = f"MAJORITY ({agreeing}/{total_models})", "MEDIUM"

    return {
        "verdict":         final_verdict,
        "weighted_score":  round(weighted_score, 4),
        "confidence":      round(abs(weighted_score - 0.5) * 2, 3),
        "agreement":       agreement_label,
        "agreement_pct":   round(agreement_pct * 100),
        "conf_level":      conf_level,
        "votes_malicious": votes_malicious,
        "votes_benign":    votes_benign,
        "individual":      individual,
        "model_used":      "ensemble",
        "mode":            individual[MODEL_OPTIONS[0]]["mode"]
    }


# ─────────────────────────────────────────────────────────────────────────────
# FINAL VERDICT LOGIC
# ─────────────────────────────────────────────────────────────────────────────

def compute_final_verdict(layer0: dict, layer1: dict) -> dict:

    # Layer 0: definitive malicious hash
    if layer0.get("known") and layer0.get("verdict") == "malicious":
        return {
            "verdict":        "MALICIOUS",
            "risk_level":     "CRITICAL",
            "triggered_by":   "Layer 0 (hash reputation)",
            "recommendation": "Block immediately. Known malware hash confirmed by reputation database.",
            "confidence":     layer0.get("confidence", 1.0)
        }

    is_ensemble = layer1.get("model_used") == "ensemble"
    l1_score    = layer1.get("weighted_score" if is_ensemble else "score") or 0
    l1_verdict  = layer1.get("verdict", "unknown")
    l1_conf     = layer1.get("confidence", 0)
    conf_level  = layer1.get("conf_level", "HIGH")
    src         = "ensemble (5 models)" if is_ensemble else f"model: {layer1.get('model_used','')}"

    # Layer 0: known benign but model disagrees
    if layer0.get("known") and layer0.get("verdict") == "benign":
        if l1_score > 0.7:
            return {
                "verdict":        "SUSPICIOUS",
                "risk_level":     "MEDIUM",
                "triggered_by":   f"Layer 1 ({src} override)",
                "recommendation": "Known-benign hash but model flags as suspicious. Manual review recommended.",
                "confidence":     round(l1_score, 3)
            }
        return {
            "verdict":        "BENIGN",
            "risk_level":     "LOW",
            "triggered_by":   "Layer 0 (hash reputation)",
            "recommendation": "File matches known benign hash. Safe to proceed.",
            "confidence":     0.95
        }

    # Unknown hash — rely entirely on Layer 1
    if l1_verdict == "malicious":
        risk = "HIGH" if l1_conf > 0.6 else "MEDIUM"
        return {
            "verdict":        "MALICIOUS",
            "risk_level":     risk,
            "triggered_by":   f"Layer 1 ({src})",
            "recommendation": "Malicious patterns detected in static analysis. Quarantine and run dynamic analysis.",
            "confidence":     round(l1_score, 3)
        }

    if l1_verdict == "benign":
        return {
            "verdict":        "BENIGN",
            "risk_level":     "LOW",
            "triggered_by":   f"Layer 1 ({src})",
            "recommendation": "No malicious patterns detected in static analysis.",
            "confidence":     round(1 - l1_score, 3)
        }

    return {
        "verdict":        "UNKNOWN",
        "risk_level":     "MEDIUM",
        "triggered_by":   "None",
        "recommendation": "Could not determine verdict. Run dynamic analysis.",
        "confidence":     0
    }


# ─────────────────────────────────────────────────────────────────────────────
# API ENDPOINTS
# ─────────────────────────────────────────────────────────────────────────────

@app.get("/")
def root():
    return FileResponse("static/index.html")


@app.get("/api/models")
def list_models():
    """List all models and their availability."""
    available = []
    for name in MODEL_OPTIONS:
        path = MODEL_DIR / f"{name}.h5"
        available.append({
            "name":      name,
            "label":     name.replace("_", " ").upper(),
            "available": path.exists(),
            "weight":    MODEL_WEIGHTS[name]
        })
    return {"models": available}


@app.post("/api/analyze")
async def analyze(
    file:       UploadFile = File(...),
    model_name: str        = Form("ensemble")
):
    """
    Full analysis pipeline:
      Layer 0 → Hash reputation (VirusTotal)
      Layer 1 → Static PE image analysis (single model or ensemble)
    """
    valid_options = MODEL_OPTIONS + [ENSEMBLE_NAME]
    if model_name not in valid_options:
        raise HTTPException(400, f"Unknown model. Choose from: {valid_options}")

    file_bytes = await file.read()
    if not file_bytes:
        raise HTTPException(400, "Empty file uploaded.")

    filename = file.filename or "unknown"
    sha256   = hashlib.sha256(file_bytes).hexdigest()

    # ── LAYER 0 ───────────────────────────────────────────────────────────────
    t0     = time.time()
    layer0 = mock_virustotal_lookup(sha256)
    layer0["duration_ms"] = round((time.time() - t0) * 1000)

    # ── LAYER 1 ───────────────────────────────────────────────────────────────
    t1        = time.time()
    img_array = pe_to_rgb_image(file_bytes)

    if img_array is None:
        layer1 = {
            "error":      "File too small to convert to image",
            "verdict":    "unknown",
            "score":      None,
            "model_used": model_name
        }
    elif model_name == ENSEMBLE_NAME:
        layer1 = run_ensemble(img_array)
    else:
        layer1 = predict_single(img_array, model_name)
        n_rgb  = len(file_bytes) // 3
        layer1["image_original_side"] = int(np.sqrt(n_rgb)) + 1

    layer1["duration_ms"] = round((time.time() - t1) * 1000)

    final_verdict = compute_final_verdict(layer0, layer1)

    return {
        "filename":          filename,
        "file_size_bytes":   len(file_bytes),
        "sha256":            sha256,
        "layer0":            layer0,
        "layer1":            layer1,
        "final_verdict":     final_verdict,
        "total_duration_ms": layer0["duration_ms"] + layer1["duration_ms"]
    }


@app.get("/api/health")
def health():
    """Health check — shows loaded models and system status."""
    return {
        "status":        "ok",
        "version":       "1.2.0",
        "tensorflow":    TF_AVAILABLE,
        "pillow":        PIL_AVAILABLE,
        "models_dir":    str(MODEL_DIR.absolute()),
        "models_available": {
            name: (MODEL_DIR / f"{name}.h5").exists()
            for name in MODEL_OPTIONS
        },
        "models_loaded": list(_loaded_models.keys())
    }


# =============================================================================
# LAYER 2 — DYNAMIC ANALYSIS
# =============================================================================
# Imports added here to keep them isolated from Layer 0/1 dependencies
import tempfile
import os as _os

try:
    import joblib as _joblib
    JOBLIB_AVAILABLE = True
except ImportError:
    JOBLIB_AVAILABLE = False

try:
    from dynamic_features import extract_features_from_pcap, features_to_vector, FEATURE_COLUMNS
    DYNAMIC_FEATURES_AVAILABLE = True
except ImportError:
    DYNAMIC_FEATURES_AVAILABLE = False

# ── Dynamic model cache ───────────────────────────────────────────────────────
_dynamic_models: dict = {}

DYNAMIC_MODEL_OPTIONS = {
    "random_forest": "random_forest_model.joblib",
    "deep_learning": "DL_model.keras",
}

def load_dynamic_model(model_name: str = "random_forest"):
    """Load and cache a dynamic analysis model."""
    if model_name in _dynamic_models:
        return _dynamic_models[model_name]

    filename = DYNAMIC_MODEL_OPTIONS.get(model_name)
    if not filename:
        return None

    path = MODEL_DIR / filename
    if not path.exists():
        print(f"[Layer2] Model not found: {path}")
        return None

    try:
        if filename.endswith(".joblib"):
            if not JOBLIB_AVAILABLE:
                return None
            m = _joblib.load(str(path))
        elif filename.endswith(".keras"):
            if not TF_AVAILABLE:
                return None
            m = tf.keras.models.load_model(str(path))
        else:
            return None
        _dynamic_models[model_name] = m
        print(f"[Layer2] Loaded dynamic model: {model_name}")
        return m
    except Exception as e:
        print(f"[Layer2] Error loading {model_name}: {e}")
        return None


def run_dynamic_inference(pcap_path: str, model_name: str = "random_forest") -> dict:
    """
    Run Layer 2 dynamic inference on a .pcap file.
    Steps:
      1. Extract 39 network features (exact notebook logic)
      2. Convert to ordered feature vector
      3. Run Random Forest or Deep Learning model
      4. Return verdict + feature summary
    """
    # Step 1: Extract features
    if not DYNAMIC_FEATURES_AVAILABLE:
        return {"error": "dynamic_features module not available", "verdict": "unknown"}

    features = extract_features_from_pcap(pcap_path)
    if features is None:
        return {"error": "Could not extract features from pcap", "verdict": "unknown"}

    # Step 2: Build DataFrame exactly as in training
    # The RF Pipeline uses ColumnTransformer with named columns —
    # must pass a pandas DataFrame (not numpy array).
    import pandas as _pd
    import warnings as _warnings
    _warnings.filterwarnings('ignore')

    cat_cols = ['protocols', 'query_types']
    num_cols = [c for c in FEATURE_COLUMNS if c not in cat_cols]

    row = {}
    for col in FEATURE_COLUMNS:
        val = features.get(col)
        if val is None:
            row[col] = 0 if col not in cat_cols else 'None'
        elif col in cat_cols:
            # Keep as string (categorical) — e.g. "6,17" or "65,1,12"
            row[col] = str(val) if val else 'None'
        else:
            try:
                row[col] = float(val)
            except (TypeError, ValueError):
                row[col] = 0.0

    df_input = _pd.DataFrame([row])
    for c in num_cols:
        df_input[c] = _pd.to_numeric(df_input[c], errors='coerce').fillna(0)

    # Step 3: Load model and predict
    model = load_dynamic_model(model_name)

    if model is None:
        # Demo mode
        import random
        score = round(random.uniform(0.05, 0.95), 4)
        verdict = "malware" if score > 0.5 else "benign"
        return {
            "verdict":        verdict,
            "score":          score,
            "confidence":     round(abs(score - 0.5) * 2, 3),
            "model_used":     model_name,
            "mode":           "demo (model not found)",
            "num_packets":    features.get("num_packets", 0),
            "tcp_ratio":      round(features.get("tcp_ratio", 0) or 0, 3),
            "udp_ratio":      round(features.get("udp_ratio", 0) or 0, 3),
            "dns_queries":    features.get("dns_query_count", 0),
            "unique_domains": features.get("unique_domain_count", 0),
            "mean_entropy":   round(features.get("mean_entropy", 0) or 0, 3),
            "total_payload":  features.get("total_payload_size", 0),
        }

    try:
        if model_name == "random_forest":
            # RF Pipeline expects DataFrame with named columns
            prediction = model.predict(df_input)[0]
            proba      = model.predict_proba(df_input)[0]
            classes    = list(model.classes_)
            mal_idx    = classes.index("malware") if "malware" in classes else 1
            score      = float(proba[mal_idx])
            verdict    = str(prediction)

        elif model_name == "deep_learning":
            import numpy as _np_dl
            X   = _np_dl.array([[row[c] if c not in cat_cols else 0
                                  for c in FEATURE_COLUMNS]])
            raw = model.predict(X, verbose=0)
            score   = float(raw[0][0]) if raw.shape[-1] == 1 else float(raw[0][1])
            verdict = "malware" if score > 0.5 else "benign"

        else:
            return {"error": f"Unknown model: {model_name}", "verdict": "unknown"}

        return {
            "verdict":        verdict,
            "score":          round(score, 4),
            "confidence":     round(abs(score - 0.5) * 2, 3),
            "model_used":     model_name,
            "mode":           "inference",
            # Key features for dashboard display
            "num_packets":    features.get("num_packets", 0),
            "tcp_ratio":      round(features.get("tcp_ratio", 0), 3),
            "udp_ratio":      round(features.get("udp_ratio", 0), 3),
            "dns_queries":    features.get("dns_query_count", 0),
            "unique_domains": features.get("unique_domain_count", 0),
            "mean_entropy":   round(features.get("mean_entropy", 0), 3),
            "total_payload":  features.get("total_payload_size", 0),
            "syn_ratio":      round(features.get("SYN", 0), 3),
            "unique_dst_ips": features.get("unique_dst_ips", 0),
        }

    except Exception as e:
        return {"error": str(e), "verdict": "unknown"}


# ── Layer 2 endpoint ──────────────────────────────────────────────────────────

@app.post("/api/analyze/dynamic")
async def analyze_dynamic(
    pcap_file:  UploadFile = File(...),
    model_name: str        = Form("random_forest")
):
    """
    Layer 2 — Dynamic Analysis endpoint.
    Upload a .pcap file captured during malware execution in the sandbox VM.
    Returns: 39-feature extraction + Random Forest / Deep Learning verdict.

    Workflow:
      ClientServerAnalyzer (Windows VM) captures pcap during execution
      → Upload pcap here
      → Feature extraction → model inference → verdict
    """
    if model_name not in DYNAMIC_MODEL_OPTIONS:
        raise HTTPException(400, f"Unknown model. Choose from: {list(DYNAMIC_MODEL_OPTIONS.keys())}")

    pcap_bytes = await pcap_file.read()
    if not pcap_bytes:
        raise HTTPException(400, "Empty pcap file uploaded.")

    filename = pcap_file.filename or "unknown.pcap"

    # Save pcap to temp file for scapy to read
    with tempfile.NamedTemporaryFile(suffix=".pcap", delete=False) as tmp:
        tmp.write(pcap_bytes)
        tmp_path = tmp.name

    try:
        t0     = time.time()
        result = run_dynamic_inference(tmp_path, model_name)
        result["duration_ms"] = round((time.time() - t0) * 1000)
        result["filename"]    = filename
        result["file_size_bytes"] = len(pcap_bytes)

        # Map verdict to final recommendation
        verdict = result.get("verdict", "unknown")
        score   = result.get("score", 0.5)
        conf    = result.get("confidence", 0)

        if verdict == "malware":
            risk = "HIGH" if conf > 0.6 else "MEDIUM"
            recommendation = "Dynamic analysis confirms malicious network behaviour. Quarantine immediately."
        elif verdict == "benign":
            recommendation = "No malicious network patterns detected in dynamic analysis."
        else:
            risk = "MEDIUM"
            recommendation = "Dynamic analysis inconclusive. Manual review recommended."

        result["risk_level"]     = "HIGH" if verdict == "malware" and conf > 0.6 else \
                                   "MEDIUM" if verdict in ["malware", "unknown"] else "LOW"
        result["recommendation"] = recommendation
        return result

    finally:
        try:
            _os.unlink(tmp_path)
        except Exception:
            pass


@app.on_event("startup")
def preload_models():
    """Pre-load all models at startup to avoid first-request timeout."""
    print("[XDR] Pre-loading static models...")
    for name in MODEL_OPTIONS:
        try:
            m = load_model(name)
            status = "OK" if m else "NOT FOUND"
        except Exception as e:
            status = f"ERROR: {str(e)[:50]}"
        print(f"[XDR]   {name}: {status}")

    print("[XDR] Pre-loading dynamic models...")
    for name in DYNAMIC_MODEL_OPTIONS:
        try:
            m = load_dynamic_model(name)
            status = "OK" if m else "NOT FOUND"
        except Exception as e:
            status = f"ERROR: {str(e)[:50]}"
        print(f"[XDR]   {name}: {status}")

    print("[XDR] All models ready.")
