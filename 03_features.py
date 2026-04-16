"""
Estágio 3 — Extração e serialização de features.
Lê:    data/interim/02_curated.csv
Saída: data/processed/X.npz, data/processed/y.csv
       models/word_tfidf.joblib, models/char_tfidf.joblib,
       models/manual_scaler.joblib, models/feature_scaler.joblib

Mapeamento de labels numéricos:
  0 = sqli
  1 = xss
  2 = benign
"""

import re
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import MaxAbsScaler

warnings.filterwarnings("ignore")

BASE_DIR = Path(__file__).parent
INTERIM_DIR = BASE_DIR / "data" / "interim"
PROCESSED_DIR = BASE_DIR / "data" / "processed"
MODELS_DIR = BASE_DIR / "models"

PROCESSED_DIR.mkdir(parents=True, exist_ok=True)
MODELS_DIR.mkdir(parents=True, exist_ok=True)

INPUT_FILE = INTERIM_DIR / "02_curated.csv"

# Mapeamento canônico de label textual → numérico
LABEL_MAP = {
    "sqli":   0,
    "xss":    1,
    "benign": 2,
}
LABEL_MAP_INV = {v: k for k, v in LABEL_MAP.items()}

# Keywords para features manuais
SQL_KEYWORDS = [
    "select", "union", "insert", "drop", "update", "delete", "where",
    "having", "exec", "xp_", "information_schema", "sleep", "benchmark",
    "cast", "convert",
]
XSS_KEYWORDS = [
    "script", "onerror", "onload", "alert", "javascript", "iframe",
    "document.", "cookie", "eval(", "src=", "href=", "onclick",
]


# ---------------------------------------------------------------------------
# Features manuais estruturais (15 features)
# ---------------------------------------------------------------------------

def extract_manual_features(payloads: pd.Series) -> np.ndarray:
    """Extrai 15 features estruturais de cada payload."""
    n = len(payloads)
    features = np.zeros((n, 15), dtype=np.float32)

    pat_1eq1   = re.compile(r"\d+=\d+")
    pat_script = re.compile(r"<\s*script", re.IGNORECASE)
    pat_handler = re.compile(r"on\w+\s*=", re.IGNORECASE)

    for i, payload in enumerate(payloads):
        p = payload if isinstance(payload, str) else ""
        p_lower = p.lower()

        features[i, 0]  = len(p)
        features[i, 1]  = p.count("'")
        features[i, 2]  = p.count('"')
        features[i, 3]  = p.count("<")
        features[i, 4]  = p.count(">")
        features[i, 5]  = p.count(";")
        features[i, 6]  = p.count("(")
        features[i, 7]  = p.count("%")
        features[i, 8]  = p.count("--")
        features[i, 9]  = p.count("/*")
        features[i, 10] = sum(1 for kw in SQL_KEYWORDS if kw in p_lower)
        features[i, 11] = sum(1 for kw in XSS_KEYWORDS if kw in p_lower)
        features[i, 12] = 1.0 if pat_1eq1.search(p) else 0.0
        features[i, 13] = 1.0 if pat_script.search(p) else 0.0
        features[i, 14] = 1.0 if pat_handler.search(p) else 0.0

    return features


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("ESTÁGIO 3 — Extração de features")
    print("=" * 60)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Arquivo de entrada não encontrado: {INPUT_FILE}")

    df = pd.read_csv(INPUT_FILE, dtype=str)
    df["payload"] = df["payload"].fillna("")

    # Validar labels
    labels_invalidos = ~df["label"].isin(LABEL_MAP.keys())
    if labels_invalidos.any():
        print(f"  [AVISO] {labels_invalidos.sum()} linhas com label inválido — removendo.")
        df = df[~labels_invalidos]

    print(f"\nTotal de amostras: {len(df):,}")
    print("Distribuição por label:")
    counts = df["label"].value_counts()
    total = len(df)
    for label, cnt in counts.items():
        num = LABEL_MAP[label]
        print(f"  {label:10s} ({num}): {cnt:7,d}  ({cnt/total*100:.1f}%)")

    payloads = df["payload"]

    # Codificação numérica dos labels — 0=sqli, 1=xss, 2=benign
    y_num = df["label"].map(LABEL_MAP).astype(int)

    # --- TF-IDF Word N-grams ---
    print("\n[1/5] Ajustando TF-IDF Word N-grams (1,2)...")
    word_tfidf = TfidfVectorizer(
        analyzer="word",
        ngram_range=(1, 2),
        max_features=8000,
        sublinear_tf=True,
        min_df=2,
        token_pattern=r"(?u)\b\w+\b|[<>'\";()%=]",
    )
    X_word = word_tfidf.fit_transform(payloads)
    print(f"  Shape X_word: {X_word.shape}")

    # --- TF-IDF Char N-grams ---
    print("[2/5] Ajustando TF-IDF Char N-grams (3,5)...")
    char_tfidf = TfidfVectorizer(
        analyzer="char_wb",
        ngram_range=(3, 5),
        max_features=12000,
        sublinear_tf=True,
        min_df=3,
    )
    X_char = char_tfidf.fit_transform(payloads)
    print(f"  Shape X_char: {X_char.shape}")

    # --- Features manuais (normalizadas individualmente) ---
    print("[3/5] Calculando features manuais estruturais (15 features)...")
    X_manual_dense = extract_manual_features(payloads)
    manual_scaler = MaxAbsScaler()
    X_manual_scaled = manual_scaler.fit_transform(X_manual_dense)
    X_manual_sparse = sp.csr_matrix(X_manual_scaled)
    print(f"  Shape X_manual: {X_manual_sparse.shape}")

    # --- Concatenação horizontal ---
    print("[4/5] Concatenando features...")
    X = sp.hstack([X_word, X_char, X_manual_sparse], format="csr")
    print(f"  Shape pré-normalização: {X.shape}")
    print(f"  Densidade: {X.nnz / (X.shape[0] * X.shape[1]) * 100:.3f}%")

    # --- Normalização global da matriz completa ---
    # MaxAbsScaler em matriz esparsa: escala cada feature para [-1, 1]
    # preservando a esparsidade e sem centralizar (não quebra features TF-IDF)
    print("[5/5] Normalizando X completo com MaxAbsScaler...")
    feature_scaler = MaxAbsScaler()
    X = feature_scaler.fit_transform(X)
    print(f"  Shape final X: {X.shape}")

    # --- Serializar vetorizadores e scalers ---
    joblib.dump(word_tfidf,     MODELS_DIR / "word_tfidf.joblib")
    print(f"\n[SALVO] {MODELS_DIR / 'word_tfidf.joblib'}")
    joblib.dump(char_tfidf,     MODELS_DIR / "char_tfidf.joblib")
    print(f"[SALVO] {MODELS_DIR / 'char_tfidf.joblib'}")
    joblib.dump(manual_scaler,  MODELS_DIR / "manual_scaler.joblib")
    print(f"[SALVO] {MODELS_DIR / 'manual_scaler.joblib'}")
    joblib.dump(feature_scaler, MODELS_DIR / "feature_scaler.joblib")
    print(f"[SALVO] {MODELS_DIR / 'feature_scaler.joblib'}")

    # --- Salvar X e y ---
    x_path = PROCESSED_DIR / "X.npz"
    y_path = PROCESSED_DIR / "y.csv"

    sp.save_npz(str(x_path), X)
    size_mb = x_path.stat().st_size / (1024 * 1024)
    print(f"[SALVO] {x_path}  (shape={X.shape}, {size_mb:.1f} MB)")

    # y.csv com label textual E numérico lado a lado
    y_df = pd.DataFrame({
        "label":     df["label"].values,
        "label_num": y_num.values,   # 0=sqli, 1=xss, 2=benign
    })
    y_df.to_csv(y_path, index=True)
    print(f"[SALVO] {y_path}  ({len(y_df):,} labels)  [colunas: label, label_num]")
    print(f"\n  Mapeamento numérico:")
    for txt, num in LABEL_MAP.items():
        print(f"    {num} = {txt}")

    print("\n[OK] Estágio 3 concluído.")


if __name__ == "__main__":
    main()
