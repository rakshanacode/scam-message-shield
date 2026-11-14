# Scam Message Shield

A small web app that checks an SMS or WhatsApp message and says **SCAM / SUSPICIOUS / LOOKS SAFE**, with simple reasons and what to do next. Built as a learning project on cybersecurity + machine learning, focused on scams common in India (fake KYC, OTP fraud, job and lottery scams, fake parcel and e-challan links).

## How it works
1. **Rule engine** (`rules.py`): 12 plain-language red-flag rules plus link checks (asks for OTP/PIN, urgency, odd link domains, fee requests, fake jobs...).
2. **ML model** (`train_model.py`): TF-IDF + Logistic Regression trained on labelled messages.
3. **Combiner** (`analyzer.py`): final risk score = 50% ML + 50% rules, with the reasons shown to the user.
4. **Web app** (`app.py`): Flask page with CSRF protection, input validation, rate limiting, security headers. Messages are never stored.

## Run
```
pip install -r requirements.txt
python train_model.py
python app.py          # open http://127.0.0.1:5000
python -m unittest discover -s tests -v
```

## Results (small dataset, 80 messages, 25% held out)
Report your own numbers after adding more data. On a dataset this small, results are only indicative.

## Limitations
- English only; small dataset; scammers change wording quickly.
- Can give false positives (for example a friend asking you to send money) and false negatives.
- Learning prototype, not a replacement for bank or police tools.

## Report scams (India)
- Suspicious message, no money lost: Chakshu on sancharsaathi.gov.in
- Money lost: call 1930 and file a complaint at cybercrime.gov.in

## Future work
Tamil and Hinglish support, a larger real dataset, a browser or WhatsApp share-sheet version.
