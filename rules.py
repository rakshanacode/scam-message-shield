import re
from textutils import URL_RE

SHORTENERS = r"\b(bit\.ly|tinyurl\.com|rb\.gy|cutt\.ly|is\.gd|t\.co|goo\.gl|wa\.me|t\.me)\b"
BAD_TLDS = r"\.(xyz|top|click|icu|buzz|live|site)\b"

# (rule_id, weight, regex, plain-language reason)
RULES = [
    ("asks_secret", 3.0, r"\b(share|send|tell|give|provide|enter|confirm|submit)\b.{0,40}\b(otp|pin|cvv|password|card number|bank details|account number|aadhaar)\b",
     "Asks you to share a secret (OTP, PIN, CVV, password, card or Aadhaar details). Real banks never ask for these."),
    ("remote_or_apk", 3.0, r"\b(anydesk|teamviewer|quicksupport)\b|\.apk\b|\binstall\b.{0,25}\bapp\b",
     "Asks you to install an app or remote-access tool. Scammers use this to take control of your phone."),
    ("fear_threat", 2.0, r"\b(arrest|police case|illegal|legal action|court notice|investigation|cyber cell|fined?)\b",
     "Uses fear or threats (arrest, police, legal action) to make you panic."),
    ("urgency", 1.5, r"\b(urgent(ly)?|immediately|tonight|expires?|expiring|last chance|final notice|at once|right now)\b|\bwill be (blocked|suspended|deactivated|disconnected|cut|deleted)\b|\bwithin \d+ ?(hours?|hrs|minutes?|mins)\b",
     "Creates false urgency (act now, blocked today, expires soon) so you don't think."),
    ("kyc_authority", 2.0, r"\b(kyc|pan|aadhaar|rbi|income tax|customs|trai|sim)\b.{0,60}\b(update|verify|blocked|deactivat\w*|link|expire\w*|pending|refund)\b",
     "Pretends to be a bank or government body asking for KYC/PAN/Aadhaar updates."),
    ("money_request", 2.0, r"\b(pay|fee|charge|deposit|transfer|send)\b.{0,30}(rs\.?|inr|\u20b9)\s?[\d,]+|(rs\.?|inr|\u20b9)\s?[\d,]+.{0,30}\b(fee|charge|deposit)\b",
     "Asks you to pay or send money (fee, deposit, charge) before you get anything."),
    ("upi_collect", 2.5, r"\bcollect request\b|\bapprove\b.{0,30}\b(pin|request)\b",
     "Asks you to approve a UPI collect request or enter your PIN. Entering your PIN only ever SENDS money; you never need it to receive money."),
    ("account_lock", 2.0, r"\b(account|net ?banking|card|sim|number)\b.{0,30}\b(locked|on hold|frozen|freeze|suspended|blocked)\b",
     "Says your account, card or SIM is locked or blocked to push you into clicking or calling."),
    ("prize_bait", 1.5, r"\b(you have won|you won|won rs|winner|lottery|lucky draw|congratulations|cashback|reward points|free|gift voucher|selected for|scholarship)\b",
     "Offers a prize, reward or free gift you never asked for."),
    ("job_bait", 2.5, r"\b(work from home|part.?time job|data entry|earn)\b.{0,50}\b(per day|daily|per task|weekly|registration|joining)\b|\bsecurity deposit\b|\bregistration fee\b",
     "Looks like a fake job offer (high pay for easy work, or a fee to join)."),
    ("invest_bait", 2.5, r"\b(guaranteed|double your|[0-9]x)\b.{0,40}\b(return|returns|profit|money)\b|\binvest\b.{0,40}\bget\b",
     "Promises unrealistic investment returns."),
    ("unsafe_contact", 1.0, r"\b(call|contact|whatsapp|telegram)\b.{0,40}(\+?\d[\d x-]{8,}|wa\.me|t\.me)",
     "Pushes you to contact an unknown number or WhatsApp/Telegram."),
]

def _negated(text, start):
    before = text[max(0, start - 14):start]
    return bool(re.search(r"(do not|don't|dont|never|not)\s*$", before))

def run_rules(text):
    t = text.lower()
    hits = []
    for rid, w, pattern, reason in RULES:
        m = None
        for cand in re.finditer(pattern, t):
            if rid == "asks_secret" and _negated(t, cand.start()):
                continue
            m = cand
            break
        if m:
            hits.append({"id": rid, "weight": w, "reason": reason})
    # link rules (checked on the original text)
    if re.search(SHORTENERS, t):
        hits.append({"id": "short_link", "weight": 1.5, "reason": "Contains a shortened link that hides the real website."})
    elif re.search(BAD_TLDS, t):
        hits.append({"id": "odd_domain", "weight": 2.0, "reason": "Link uses an unusual domain ending (.xyz, .top, .click, .icu...) common in scams."})
    elif URL_RE.search(t):
        hits.append({"id": "has_link", "weight": 0.5, "reason": "Contains a link. Never tap links in unexpected messages; type the official site yourself."})
    return hits

def rule_score(hits):
    return sum(h["weight"] for h in hits)
