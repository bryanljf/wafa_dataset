"""
Estágio 4 — Treino, cross-validation e avaliação do Random Forest.
Lê:    data/processed/X.npz, data/processed/y.csv
Saída: models/random_forest.joblib, reports/metrics_test.json
       data/processed/indices_{train,val,test}.npy

Mapeamento de labels numéricos:
  0 = sqli
  1 = xss
  2 = benign
"""

import gc
import json
import time
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp
from imblearn.over_sampling import RandomOverSampler
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    classification_report,
    confusion_matrix,
    f1_score,
    recall_score,
)
from sklearn.model_selection import StratifiedKFold, StratifiedShuffleSplit

warnings.filterwarnings("ignore")

SEED = 42
BASE_DIR = Path(__file__).parent
PROCESSED_DIR = BASE_DIR / "data" / "processed"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

MODELS_DIR.mkdir(parents=True, exist_ok=True)
REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Labels numéricos canônicos
LABEL_MAP     = {"sqli": 0, "xss": 1, "benign": 2}
LABEL_MAP_INV = {0: "sqli", 1: "xss", 2: "benign"}
LABELS_NUM    = [0, 1, 2]
LABELS_STR    = ["sqli", "xss", "benign"]


# ---------------------------------------------------------------------------
# Métricas auxiliares
# ---------------------------------------------------------------------------

def compute_fpr(y_true: np.ndarray, y_pred: np.ndarray) -> float:
    """FPR = FP_benign / (FP_benign + TN_benign)."""
    cm = confusion_matrix(y_true, y_pred, labels=LABELS_NUM)
    # Linha 2 = benign real; coluna 2 = benign predito
    tn = cm[2, 2]
    fp = cm[2, 0] + cm[2, 1]   # benign predito como sqli ou xss
    return fp / (fp + tn) if (fp + tn) > 0 else 0.0


def cv_metrics(clf, X, y: np.ndarray, k: int = 5) -> dict:
    """Cross-validation estratificado com k folds."""
    skf = StratifiedKFold(n_splits=k, shuffle=True, random_state=SEED)
    results = {
        "recall_sqli": [], "recall_xss": [], "recall_benign": [],
        "f1_macro": [], "fpr": [],
    }

    for fold, (tr_idx, val_idx) in enumerate(skf.split(X, y), 1):
        X_tr, X_vl = X[tr_idx], X[val_idx]
        y_tr, y_vl = y[tr_idx], y[val_idx]

        # Balancear apenas o fold de treino
        ros = RandomOverSampler(random_state=SEED)
        X_tr_bal, y_tr_bal = ros.fit_resample(X_tr, y_tr)

        clf.fit(X_tr_bal, y_tr_bal)
        y_pred = clf.predict(X_vl)

        r_sqli   = recall_score(y_vl, y_pred, labels=[0], average="micro", zero_division=0)
        r_xss    = recall_score(y_vl, y_pred, labels=[1], average="micro", zero_division=0)
        r_benign = recall_score(y_vl, y_pred, labels=[2], average="micro", zero_division=0)
        f1       = f1_score(y_vl, y_pred, labels=LABELS_NUM, average="macro", zero_division=0)
        fpr      = compute_fpr(y_vl, y_pred)

        results["recall_sqli"].append(r_sqli)
        results["recall_xss"].append(r_xss)
        results["recall_benign"].append(r_benign)
        results["f1_macro"].append(f1)
        results["fpr"].append(fpr)

        print(f"    Fold {fold}/{k} — recall_sqli={r_sqli:.3f}  recall_xss={r_xss:.3f}  "
              f"f1={f1:.3f}  FPR={fpr:.4f}")

    print("\n  Resumo CV (mean ± std):")
    summary = {}
    for key, vals in results.items():
        m, s = np.mean(vals), np.std(vals)
        summary[key] = {"mean": round(m, 4), "std": round(s, 4)}
        print(f"    {key:20s}: {m:.4f} ± {s:.4f}")
    return summary


# ---------------------------------------------------------------------------
# Latência de inferência — simula middleware de produção
# ---------------------------------------------------------------------------

def measure_latency_p95(clf, X_test: sp.csr_matrix, n_samples: int = 1000) -> float:
    """Inferência uma amostra por vez; retorna p95 em ms."""
    n = min(n_samples, X_test.shape[0])
    indices = np.random.choice(X_test.shape[0], n, replace=False)
    latencies = []
    for idx in indices:
        row = X_test[idx]
        t0 = time.perf_counter()
        clf.predict(row)
        latencies.append((time.perf_counter() - t0) * 1000)
    return float(np.percentile(latencies, 95))


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("ESTÁGIO 4 — Treino e Validação")
    print("=" * 60)

    x_path = PROCESSED_DIR / "X.npz"
    y_path = PROCESSED_DIR / "y.csv"

    if not x_path.exists() or not y_path.exists():
        raise FileNotFoundError("Arquivos X.npz ou y.csv não encontrados. Execute o estágio 3.")

    print("\n[1/6] Carregando dados...")
    X = sp.load_npz(str(x_path))
    y_df = pd.read_csv(y_path, index_col=0)

    # Usar label_num (0=sqli, 1=xss, 2=benign)
    if "label_num" not in y_df.columns:
        raise ValueError("Coluna 'label_num' não encontrada em y.csv. Re-execute o estágio 3.")
    y = y_df["label_num"].values.astype(int)

    print(f"  Shape X: {X.shape}")
    print(f"  Total amostras: {len(y):,}")
    print("  Distribuição (antes do balanceamento):")
    for num, txt in LABEL_MAP_INV.items():
        cnt = (y == num).sum()
        print(f"    {num} ({txt:6s}): {cnt:,}")

    # --- Split estratificado 70/15/15 ---
    print("\n[2/6] Dividindo dados (70% treino / 15% val / 15% teste)...")
    sss1 = StratifiedShuffleSplit(n_splits=1, test_size=0.30, random_state=SEED)
    train_idx, temp_idx = next(sss1.split(X, y))

    sss2 = StratifiedShuffleSplit(n_splits=1, test_size=0.50, random_state=SEED)
    val_rel, test_rel = next(sss2.split(X[temp_idx], y[temp_idx]))
    val_idx  = temp_idx[val_rel]
    test_idx = temp_idx[test_rel]

    print(f"  Treino : {len(train_idx):,}")
    print(f"  Val    : {len(val_idx):,}")
    print(f"  Teste  : {len(test_idx):,}")

    np.save(PROCESSED_DIR / "indices_train.npy", train_idx)
    np.save(PROCESSED_DIR / "indices_val.npy",   val_idx)
    np.save(PROCESSED_DIR / "indices_test.npy",  test_idx)
    print("  [SALVO] Índices de split salvos.")

    X_train, y_train = X[train_idx], y[train_idx]
    X_val,   y_val   = X[val_idx],   y[val_idx]
    X_test,  y_test  = X[test_idx],  y[test_idx]

    # --- Balanceamento do conjunto de treino ---
    print("\n[3/6] Balanceando conjunto de treino com RandomOverSampler...")
    print("  Distribuição antes:")
    for num, txt in LABEL_MAP_INV.items():
        print(f"    {num} ({txt:6s}): {(y_train == num).sum():,}")

    ros = RandomOverSampler(random_state=SEED)
    X_train_bal, y_train_bal = ros.fit_resample(X_train, y_train)

    print("  Distribuição depois:")
    for num, txt in LABEL_MAP_INV.items():
        print(f"    {num} ({txt:6s}): {(y_train_bal == num).sum():,}")
    print(f"  Total balanceado: {len(y_train_bal):,}")

    # --- Cross-validation (k=3 para economizar RAM) ---
    print("\n[4/6] Cross-validation (k=3) no conjunto de treino original...")
    print("  [INFO] Usando k=3 e n_jobs=2 para limitar RAM a ~70% do máximo")
    clf_cv = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        max_features="sqrt",
        class_weight="balanced_subsample",
        min_samples_leaf=2,
        n_jobs=2,
        random_state=SEED,
    )
    cv_summary = cv_metrics(clf_cv, X_train, y_train, k=3)
    gc.collect()  # Liberar memória após CV

    # --- Treino final no conjunto balanceado ---
    print("\n[5/6] Treinando modelo final no treino balanceado...")
    clf = RandomForestClassifier(
        n_estimators=300,
        max_depth=None,
        max_features="sqrt",
        class_weight="balanced_subsample",
        min_samples_leaf=2,
        n_jobs=2,
        random_state=SEED,
    )
    t0 = time.time()
    clf.fit(X_train_bal, y_train_bal)
    print(f"  Treino concluído em {time.time() - t0:.1f}s")
    gc.collect()  # Liberar memória após treino

    # --- Avaliação no teste ---
    print("\n[6/6] Avaliando no conjunto de teste...")
    y_pred = clf.predict(X_test)

    print("\n--- Classification Report (0=sqli, 1=xss, 2=benign) ---")
    report_str = classification_report(
        y_test, y_pred,
        labels=LABELS_NUM,
        target_names=LABELS_STR,
        digits=4,
    )
    print(report_str)

    cm = confusion_matrix(y_test, y_pred, labels=LABELS_NUM)
    print("--- Matriz de Confusão ---")
    header = f"  {'':10s}  {'pred_sqli(0)':>13s}  {'pred_xss(1)':>12s}  {'pred_benign(2)':>14s}"
    print(header)
    for i, (num, txt) in enumerate(LABEL_MAP_INV.items()):
        print(f"  {txt}({num}){' '*(7-len(txt))}  {cm[i,0]:>13,d}  {cm[i,1]:>12,d}  {cm[i,2]:>14,d}")

    fpr      = compute_fpr(y_test, y_pred)
    r_sqli   = recall_score(y_test, y_pred, labels=[0], average="micro", zero_division=0)
    r_xss    = recall_score(y_test, y_pred, labels=[1], average="micro", zero_division=0)
    f1_macro = f1_score(y_test, y_pred, labels=LABELS_NUM, average="macro", zero_division=0)

    print(f"\n  FPR  (FP_benign / FP_benign + TN_benign): {fpr:.6f}  ({fpr*100:.4f}%)")
    print(f"  Recall sqli  (0): {r_sqli:.4f}")
    print(f"  Recall xss   (1): {r_xss:.4f}")
    print(f"  F1 macro        : {f1_macro:.4f}")

    print("\n--- Latência de inferência (1 amostra/vez, n=1000) ---")
    p95_ms = measure_latency_p95(clf, X_test, n_samples=1000)
    print(f"  p95: {p95_ms:.2f} ms")

    # --- Critérios de aprovação ---
    print("\n" + "=" * 60)
    print("CRITÉRIOS DE APROVAÇÃO")
    print("=" * 60)

    def check(label, value, threshold, op=">="):
        passed = value >= threshold if op == ">=" else value <= threshold
        status = "PASS" if passed else "FAIL"
        print(f"  [{status}] {label}: {value:.4f} (threshold {op} {threshold})")
        return passed

    r1 = check("Recall sqli  (0)", r_sqli,   0.95, ">=")
    r2 = check("Recall xss   (1)", r_xss,    0.95, ">=")
    r3 = check("FPR",              fpr,      0.005, "<=")
    r4 = check("F1 macro",         f1_macro, 0.95, ">=")
    r5 = check("Latência p95 ms",  p95_ms,  50.0, "<=")

    all_pass = all([r1, r2, r3, r4, r5])
    print(f"\n  Resultado geral: {'APROVADO' if all_pass else 'REPROVADO — revisar dataset/modelo'}")

    # --- Salvar modelo ---
    model_path = MODELS_DIR / "random_forest.joblib"
    joblib.dump(clf, model_path)
    size_mb = model_path.stat().st_size / (1024 * 1024)
    print(f"\n[SALVO] {model_path}  ({size_mb:.1f} MB)")

    # --- Relatório JSON ---
    report_dict = classification_report(
        y_test, y_pred,
        labels=LABELS_NUM,
        target_names=LABELS_STR,
        output_dict=True,
    )
    metrics = {
        "label_map": LABEL_MAP,
        "classification_report": report_dict,
        "confusion_matrix": cm.tolist(),
        "fpr_explicit": round(fpr, 6),
        "recall_sqli":  round(r_sqli,   4),
        "recall_xss":   round(r_xss,    4),
        "f1_macro":     round(f1_macro, 4),
        "latency_p95_ms": round(p95_ms, 2),
        "criteria": {
            "recall_sqli_pass":  bool(r1),
            "recall_xss_pass":   bool(r2),
            "fpr_pass":          bool(r3),
            "f1_macro_pass":     bool(r4),
            "latency_pass":      bool(r5),
            "all_pass":          bool(all_pass),
        },
        "cv_summary": cv_summary,
        "split_sizes": {
            "train_original":  int(len(train_idx)),
            "train_balanced":  int(len(y_train_bal)),
            "val":             int(len(val_idx)),
            "test":            int(len(test_idx)),
        },
    }

    report_path = REPORTS_DIR / "metrics_test.json"
    with open(report_path, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    print(f"[SALVO] {report_path}")

    gc.collect()  # Liberar toda memória ao final
    print("\n[OK] Estágio 4 concluído.")


if __name__ == "__main__":
    main()
