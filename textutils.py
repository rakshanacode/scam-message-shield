import re

URL_RE = re.compile(r"(https?://\S+|www\.\S+|\b[a-z0-9-]+\.(?:com|in|xyz|top|click|icu|live|buzz|site|info|co|apk-download\.click)\b\S*|\b(?:bit\.ly|tinyurl\.com|rb\.gy|cutt\.ly|is\.gd|t\.co|goo\.gl|wa\.me|t\.me)/\S*)", re.I)

def clean_text(text):
    """Lowercase, replace links and numbers with tokens so the model learns patterns, not exact values."""
    t = text.lower()
    t = URL_RE.sub(" urltoken ", t)
    t = re.sub(r"(rs\.?|inr|\u20b9)\s?[\d,]+(\.\d+)?", " moneytoken ", t)
    t = re.sub(r"\d[\d,x]*", " numtoken ", t)
    return re.sub(r"\s+", " ", t).strip()
