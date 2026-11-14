import os, joblib, numpy as np
from rules import run_rules, rule_score
from textutils import clean_text

MODEL_PATH = os.path.join(os.path.dirname(__file__), "model.pkl")
RULE_CAP = 6.0          # rule score that counts as "maximum suspicion"
ML_WEIGHT = 0.5         # final score = 0.5*ML + 0.5*rules
SCAM_AT, SUSPICIOUS_AT = 0.60, 0.35

def load_model():
    return joblib.load(MODEL_PATH) if os.path.exists(MODEL_PATH) else None

def top_words(model, text, n=5):
    vec, clf = model["vec"], model["clf"]
    x = vec.transform([clean_text(text)])
    contrib = x.multiply(clf.coef_[0]).tocoo()
    names = vec.get_feature_names_out()
    pairs = sorted(zip(contrib.col, contrib.data), key=lambda p: -p[1])
    return [names[c] for c, v in pairs if v > 0][:n]

def analyze(text, model=None):
    hits = run_rules(text)
    rs = rule_score(hits)
    ml_prob = None
    words = []
    if model is not None:
        ml_prob = float(model["clf"].predict_proba(model["vec"].transform([clean_text(text)]))[0][1])
        words = top_words(model, text)
    rule_norm = min(rs / RULE_CAP, 1.0)
    score = rule_norm if ml_prob is None else ML_WEIGHT * ml_prob + (1 - ML_WEIGHT) * rule_norm
    label = "SCAM" if score >= SCAM_AT else "SUSPICIOUS" if score >= SUSPICIOUS_AT else "LOOKS SAFE"
    strong = [h for h in hits if h["weight"] >= 2.5]
    if strong and label == "LOOKS SAFE":
        label = "SUSPICIOUS"
    if len(strong) >= 2:
        label = "SCAM"
    return {"label": label, "score": round(score * 100), "ml_prob": None if ml_prob is None else round(ml_prob * 100),
            "rule_score": round(rs, 1), "reasons": [h["reason"] for h in hits], "words": words}
