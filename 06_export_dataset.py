"""
Estágio 6 — Exportação do dataset final em formato legível.
Lê:    data/interim/02_curated.csv, data/processed/y.csv,
       data/processed/indices_{train,val,test}.npy
Saída: data/processed/dataset_train.csv
       data/processed/dataset_val.csv
       data/processed/dataset_test.csv

Colunas exportadas:
  - index_original : índice da amostra no dataset completo
  - payload        : texto da requisição
  - label          : classe textual (sqli / xss / benign)
  - label_num      : classe numérica (0=sqli, 1=xss, 2=benign)
  - source         : arquivo de origem
  - split          : treino / validacao / teste
  - feat_len       : comprimento do payload
  - feat_apostrophe: contagem de apóstrofes
  - feat_dquote    : contagem de aspas duplas
  - feat_lt        : contagem de <
  - feat_gt        : contagem de >
  - feat_semicolon : contagem de ;
  - feat_paren     : contagem de (
  - feat_percent   : contagem de %
  - feat_dashdash  : contagem de --
  - feat_comment   : contagem de /*
  - feat_sql_kw    : soma de keywords SQL encontradas
  - feat_xss_kw    : soma de keywords XSS encontradas
  - feat_1eq1      : padrão \d+=\d+ presente (0/1)
  - feat_script_tag: tag <script presente (0/1)
  - feat_handler   : event handler on*= presente (0/1)
"""

import re
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

BASE_DIR     = Path(__file__).parent
INTERIM_DIR  = BASE_DIR / "data" / "interim"
PROCESSED_DIR = BASE_DIR / "data" / "processed"

CURATED_FILE  = INTERIM_DIR  / "02_curated.csv"
Y_FILE        = PROCESSED_DIR / "y.csv"

SQL_KEYWORDS = [
    "select", "union", "insert", "drop", "update", "delete", "where",
    "having", "exec", "xp_", "information_schema", "sleep", "benchmark",
    "cast", "convert",
]
XSS_KEYWORDS = [
    "script", "onerror", "onload", "alert", "javascript", "iframe",
    "document.", "cookie", "eval(", "src=", "href=", "onclick",
]

PAT_1EQ1   = re.compile(r"\d+=\d+")
PAT_SCRIPT = re.compile(r"<\s*script", re.IGNORECASE)
PAT_HANDLER = re.compile(r"on\w+\s*=", re.IGNORECASE)


def compute_manual_features(payloads: pd.Series) -> pd.DataFrame:
    records = []
    for p in payloads:
        p = p if isinstance(p, str) else ""
        pl = p.lower()
        records.append({
            "feat_len":        len(p),
            "feat_apostrophe": p.count("'"),
            "feat_dquote":     p.count('"'),
            "feat_lt":         p.count("<"),
            "feat_gt":         p.count(">"),
            "feat_semicolon":  p.count(";"),
            "feat_paren":      p.count("("),
            "feat_percent":    p.count("%"),
            "feat_dashdash":   p.count("--"),
            "feat_comment":    p.count("/*"),
            "feat_sql_kw":     sum(1 for kw in SQL_KEYWORDS if kw in pl),
            "feat_xss_kw":     sum(1 for kw in XSS_KEYWORDS if kw in pl),
            "feat_1eq1":       int(bool(PAT_1EQ1.search(p))),
            "feat_script_tag": int(bool(PAT_SCRIPT.search(p))),
            "feat_handler":    int(bool(PAT_HANDLER.search(p))),
        })
    return pd.DataFrame(records)


def export_split(df_full: pd.DataFrame, indices: np.ndarray, split_name: str) -> pd.DataFrame:
    df = df_full.iloc[indices].copy()
    df["split"] = split_name
    df["index_original"] = indices
    return df.reset_index(drop=True)


def main():
    print("=" * 60)
    print("ESTÁGIO 6 — Exportação do dataset final")
    print("=" * 60)

    # Verificar arquivos necessários
    for p in [CURATED_FILE, Y_FILE,
              PROCESSED_DIR / "indices_train.npy",
              PROCESSED_DIR / "indices_val.npy",
              PROCESSED_DIR / "indices_test.npy"]:
        if not p.exists():
            raise FileNotFoundError(f"Arquivo necessário não encontrado: {p}\n"
                                     "Execute os estágios 1-4 antes.")

    print("\n[1/4] Carregando dados curados...")
    df = pd.read_csv(CURATED_FILE, dtype=str)
    df["payload"] = df["payload"].fillna("")
    df["label"]   = df["label"].fillna("unknown")
    df["source"]  = df["source"].fillna("unknown")

    y_df = pd.read_csv(Y_FILE, index_col=0)
    df["label_num"] = y_df["label_num"].values

    print(f"  Total de amostras: {len(df):,}")

    print("\n[2/4] Calculando features manuais (15 features)...")
    feats = compute_manual_features(df["payload"])
    df = pd.concat([df, feats], axis=1)

    print("\n[3/4] Carregando índices de split...")
    idx_train = np.load(PROCESSED_DIR / "indices_train.npy")
    idx_val   = np.load(PROCESSED_DIR / "indices_val.npy")
    idx_test  = np.load(PROCESSED_DIR / "indices_test.npy")

    print(f"  Treino : {len(idx_train):,} amostras")
    print(f"  Val    : {len(idx_val):,} amostras")
    print(f"  Teste  : {len(idx_test):,} amostras")

    # Definir ordem de colunas do CSV exportado
    base_cols = ["index_original", "payload", "label", "label_num", "source", "split"]
    feat_cols = [c for c in df.columns if c.startswith("feat_")]
    export_cols = base_cols + feat_cols

    print("\n[4/4] Exportando splits para CSV...")

    splits = [
        (idx_train, "treino",     "dataset_train.csv"),
        (idx_val,   "validacao",  "dataset_val.csv"),
        (idx_test,  "teste",      "dataset_test.csv"),
    ]

    for indices, split_name, filename in splits:
        df_split = export_split(df, indices, split_name)
        # Garantir que index_original é colocado corretamente
        df_split["index_original"] = indices

        out_path = PROCESSED_DIR / filename
        df_split[export_cols].to_csv(out_path, index=False, encoding="utf-8-sig")
        size_mb = out_path.stat().st_size / (1024 * 1024)

        # Distribuição por label neste split
        counts = df_split["label"].value_counts()
        print(f"\n  [SALVO] {out_path}")
        print(f"          {len(df_split):,} linhas, {size_mb:.1f} MB, {len(export_cols)} colunas")
        print(f"          Distribuição:")
        for lbl, cnt in counts.items():
            print(f"            {lbl:8s}: {cnt:,}  ({cnt/len(df_split)*100:.1f}%)")

    print("\n" + "=" * 60)
    print("RESUMO DO DATASET EXPORTADO")
    print("=" * 60)
    print(f"  Colunas exportadas ({len(export_cols)}):")
    print(f"    Identificação : index_original, payload, label, label_num, source, split")
    print(f"    Features (15) : {', '.join(feat_cols)}")
    print(f"\n  Mapeamento label_num:")
    print(f"    0 = sqli")
    print(f"    1 = xss")
    print(f"    2 = benign")
    print(f"\n  Arquivos gerados em: {PROCESSED_DIR}")
    print("\n[OK] Estágio 6 concluído.")


if __name__ == "__main__":
    main()