"""
Trains the zero-day phishing URL classifier and evaluates it honestly.
  - time-based split (train on past, test on future campaigns)
  - baseline 1: Bloom filter of the training blacklist (catches only already-listed URLs)
  - baseline 2: logistic regression
  - model     : histogram gradient boosting
  - metrics   : precision, recall, F1, ROC-AUC, PR-AUC, confusion matrix, permutation importance
Usage: python -m phishstream.ml.train
"""
import json
import time

import joblib
import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier
from sklearn.inspection import permutation_importance
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (average_precision_score, confusion_matrix, f1_score, precision_score,
                             recall_score, roc_auc_score)
from sklearn.pipeline import make_pipeline
from sklearn.preprocessing import StandardScaler

from phishstream.config import METRICS_PATH, MODEL_PATH, MODEL_THRESHOLD
from phishstream.data import load, time_split
from phishstream.features.url_features import FEATURE_NAMES, extract
from phishstream.sketches.bloom import BloomFilter


def featurize(urls):
    return np.array([extract(u) for u in urls], dtype=np.float32)


def scores(y, p, thr=MODEL_THRESHOLD):
    pred = (p >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred, labels=[0, 1]).ravel()
    return {"precision": round(precision_score(y, pred, zero_division=0), 4),
            "recall": round(recall_score(y, pred, zero_division=0), 4),
            "f1": round(f1_score(y, pred, zero_division=0), 4),
            "roc_auc": round(roc_auc_score(y, p), 4) if len(set(y)) > 1 else None,
            "pr_auc": round(average_precision_score(y, p), 4) if len(set(y)) > 1 else None,
            "confusion": {"tn": int(tn), "fp": int(fp), "fn": int(fn), "tp": int(tp)},
            "false_positive_rate": round(fp / (fp + tn), 4) if fp + tn else 0}


def main():
    df = load()
    train, test, cutoff = time_split(df)
    print(f"train {len(train):,} rows (until {cutoff:%Y-%m-%d}), test {len(test):,} rows (after)")
    Xtr, ytr = featurize(train["url"]), train["label"].to_numpy()
    Xte, yte = featurize(test["url"]), test["label"].to_numpy()

    # baseline 1: blacklist only (what a Bloom filter alone can do on future URLs)
    bl = train.loc[train.label == 1, "url"]
    bf = BloomFilter.for_capacity(len(bl), 0.001)
    for u in bl:
        bf.add(u)
    p_bloom = np.array([1.0 if u in bf else 0.0 for u in test["url"]])

    t0 = time.time()
    lr = make_pipeline(StandardScaler(), LogisticRegression(max_iter=2000, class_weight="balanced"))
    lr.fit(Xtr, ytr)
    p_lr = lr.predict_proba(Xte)[:, 1]

    gb = HistGradientBoostingClassifier(max_iter=300, learning_rate=0.08, max_leaf_nodes=31,
                                        l2_regularization=1.0, class_weight="balanced", random_state=0)
    gb.fit(Xtr, ytr)
    train_s = time.time() - t0
    p_gb = gb.predict_proba(Xte)[:, 1]

    t0 = time.time()
    gb.predict_proba(Xte[:10000])
    per_url_us = (time.time() - t0) / min(10000, len(Xte)) * 1e6

    idx = np.random.default_rng(0).choice(len(Xte), min(8000, len(Xte)), replace=False)
    imp = permutation_importance(gb, Xte[idx], yte[idx], scoring="average_precision", n_repeats=3, random_state=0)
    importance = sorted(zip(FEATURE_NAMES, imp.importances_mean), key=lambda x: -x[1])[:12]

    # error analysis: which kinds of phishing the model misses
    test = test.assign(p=p_gb)
    missed = test[(test.label == 1) & (test.p < MODEL_THRESHOLD)]
    false_alarms = test[(test.label == 0) & (test.p >= MODEL_THRESHOLD)]

    metrics = {
        "split": {"cutoff": str(cutoff), "train_rows": len(train), "test_rows": len(test),
                  "test_phishing": int(yte.sum()), "test_safe": int(len(yte) - yte.sum())},
        "bloom_only": scores(yte, p_bloom),
        "logistic_regression": scores(yte, p_lr),
        "gradient_boosting": scores(yte, p_gb),
        "train_seconds": round(train_s, 1),
        "inference_us_per_url": round(per_url_us, 1),
        "feature_importance": [{"feature": f, "importance": round(float(v), 4)} for f, v in importance],
        "missed_examples": missed.sort_values("p").head(8)["url"].tolist(),
        "false_alarm_examples": false_alarms.sort_values("p", ascending=False).head(8)["url"].tolist(),
        "threshold": MODEL_THRESHOLD,
    }
    joblib.dump({"model": gb, "features": FEATURE_NAMES, "threshold": MODEL_THRESHOLD}, MODEL_PATH)
    METRICS_PATH.write_text(json.dumps(metrics, indent=2))
    for name in ("bloom_only", "logistic_regression", "gradient_boosting"):
        m = metrics[name]
        print(f"{name:20s} precision {m['precision']:.3f}  recall {m['recall']:.3f}  f1 {m['f1']:.3f}  "
              f"pr_auc {m['pr_auc']}")
    print("top features:", ", ".join(f for f, _ in importance[:6]))
    print(f"saved {MODEL_PATH.name}, {METRICS_PATH.name}")


if __name__ == "__main__":
    main()
