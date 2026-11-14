import os, joblib, pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.metrics import accuracy_score, confusion_matrix, classification_report
from textutils import clean_text
from analyzer import analyze

df = pd.read_csv("data/india_scams.csv")          # columns: text,label (1 = scam, 0 = safe)
if os.path.exists("data/SMSSpamCollection"):      # optional extra data (UCI SMS Spam Collection)
    extra = pd.read_csv("data/SMSSpamCollection", sep="\t", names=["label", "text"])
    extra["label"] = (extra["label"] == "spam").astype(int)
    df = pd.concat([df, extra.sample(n=min(500, len(extra)), random_state=1)], ignore_index=True)
df = df.dropna().drop_duplicates(subset="text")
print("Messages:", len(df), "| scam:", int(df.label.sum()), "| safe:", int((df.label == 0).sum()))

X_train, X_test, y_train, y_test = train_test_split(df["text"], df["label"], test_size=0.25, random_state=42, stratify=df["label"])
vec = TfidfVectorizer(preprocessor=clean_text, ngram_range=(1, 2), sublinear_tf=True)
clf = LogisticRegression(max_iter=1000, class_weight="balanced")
clf.fit(vec.fit_transform(X_train), y_train)
model = {"vec": vec, "clf": clf}

pred_ml = clf.predict(vec.transform(X_test))
print("\n--- ML only ---")
print("Train accuracy:", round(accuracy_score(y_train, clf.predict(vec.transform(X_train))), 3))
print("Test accuracy :", round(accuracy_score(y_test, pred_ml), 3))
print(confusion_matrix(y_test, pred_ml))
print(classification_report(y_test, pred_ml, target_names=["safe", "scam"]))

pred_all = [int(analyze(t, model)["label"] != "LOOKS SAFE") for t in X_test]
print("--- Rules + ML (SUSPICIOUS counted as flagged) ---")
print("Test accuracy :", round(accuracy_score(y_test, pred_all), 3))
print(confusion_matrix(y_test, pred_all))

cv = cross_val_score(__import__("sklearn.pipeline", fromlist=["Pipeline"]).Pipeline([("v", TfidfVectorizer(preprocessor=clean_text, ngram_range=(1, 2), sublinear_tf=True)), ("c", LogisticRegression(max_iter=1000, class_weight="balanced"))]), df["text"], df["label"], cv=5)
print("5-fold CV accuracy (ML only):", cv.round(2), "mean", round(cv.mean(), 3))
joblib.dump(model, "model.pkl")
print("Saved model.pkl")
