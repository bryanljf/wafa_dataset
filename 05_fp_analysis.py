"""
Estágio 5 — Análise de Falsos Positivos no conjunto de validação.
Lê:    models/, data/processed/X.npz, data/processed/y.csv, data/interim/02_curated.csv
Saída: reports/false_positives.csv
"""

import re
import warnings
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
import scipy.sparse as sp

warnings.filterwarnings("ignore")

BASE_DIR = Path(__file__).parent
PROCESSED_DIR = BASE_DIR / "data" / "processed"
INTERIM_DIR = BASE_DIR / "data" / "interim"
MODELS_DIR = BASE_DIR / "models"
REPORTS_DIR = BASE_DIR / "reports"

REPORTS_DIR.mkdir(parents=True, exist_ok=True)

# Mapeamento numérico canônico (deve coincidir com estágios 3 e 4)
LABEL_MAP     = {"sqli": 0, "xss": 1, "benign": 2}
LABEL_MAP_INV = {0: "sqli", 1: "xss", 2: "benign"}
LABELS_NUM    = [0, 1, 2]

SQL_WORDS = re.compile(
    r"\b(select|union|insert|drop|update|delete|where|having|exec)\b", re.IGNORECASE
)
HTML_TAG = re.compile(r"[<>]")
SCRIPT_WORD = re.compile(r"\bscript\b", re.IGNORECASE)
SCRIPT_TAG = re.compile(r"<\s*script", re.IGNORECASE)
SELECT_UNION = re.compile(r"\b(select|union)\b", re.IGNORECASE)
APOSTROPHE = re.compile(r"'")
PARAM_NUMERIC = re.compile(r"=\d")


def classify_fp_group(payload: str) -> str:
    """Categoriza o FP em grupos para orientar enriquecimento do dataset."""
    has_apostrophe = bool(APOSTROPHE.search(payload))
    has_sql_word = bool(SQL_WORDS.search(payload))
    has_html_tag = bool(HTML_TAG.search(payload))
    has_script_word = bool(SCRIPT_WORD.search(payload))
    has_script_tag = bool(SCRIPT_TAG.search(payload))
    has_select_union = bool(SELECT_UNION.search(payload))
    has_param_numeric = bool(PARAM_NUMERIC.search(payload))

    if has_apostrophe and has_sql_word:
        return "apostrophe_sql_word"
    if has_html_tag:
        return "html_tag_legit"
    if has_script_word and not has_script_tag:
        return "word_script_legit"
    if has_select_union:
        return "sql_word_natural"
    if has_param_numeric:
        return "param_numeric"
    return "uncategorized"


def suggest_templates(group_counts: pd.Series) -> str:
    """Gera sugestão textual de novos templates com base nos grupos mais populares."""
    suggestions = {
        "apostrophe_sql_word": (
            "Adicionar templates com nomes próprios contendo apóstrofe (ex: O'Brien, D'Almeida) "
            "combinados com termos SQL em contexto de busca legítima, ex: "
            "'busca=O'Brien+WHERE+mora' ou 'autor=D'Almeida+SELECT+livros'."
        ),
        "html_tag_legit": (
            "Adicionar templates com campos de CMS/editor rico contendo tags HTML legítimas "
            "(<p>, <b>, <div>, <h1>) em contexto de conteúdo de usuário. "
            "Ex: 'conteudo=<p>Texto normal</p>&secao=artigo'."
        ),
        "word_script_legit": (
            "Adicionar templates onde 'script' aparece como nome de arquivo .js, parâmetro de "
            "configuração ou referência técnica sem tag HTML. "
            "Ex: 'arquivo=main_script.js', 'config=script_timeout:3000'."
        ),
        "sql_word_natural": (
            "Adicionar frases de busca em linguagem natural contendo SELECT/UNION/WHERE como "
            "termos de pesquisa em fóruns, tutoriais ou descrições de produto. "
            "Ex: 'q=diferença+entre+SELECT+e+WHERE+SQL'."
        ),
        "param_numeric": (
            "Adicionar parâmetros de paginação, ID e filtros numéricos legítimos. "
            "Ex: 'page=1&id=42', 'filtro=preco:10-500', 'offset=100&limit=20'."
        ),
        "uncategorized": (
            "Revisar manualmente os FPs 'uncategorized' para identificar padrões não cobertos "
            "e criar templates específicos."
        ),
    }

    lines = ["\n=== SUGESTÕES DE NOVOS TEMPLATES PARA 01_collect.py ==="]
    for group, count in group_counts.items():
        if count > 0 and group in suggestions:
            lines.append(f"\n[{group}] ({count} FPs)")
            lines.append(f"  → {suggestions[group]}")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("ESTÁGIO 5 — Análise de Falsos Positivos")
    print("=" * 60)

    # Verificar arquivos necessários
    required = [
        PROCESSED_DIR / "X.npz",
        PROCESSED_DIR / "y.csv",
        PROCESSED_DIR / "indices_val.npy",
        MODELS_DIR / "random_forest.joblib",
        INTERIM_DIR / "02_curated.csv",
    ]
    for p in required:
        if not p.exists():
            raise FileNotFoundError(f"Arquivo necessário não encontrado: {p}")

    # Carregar artefatos
    print("\n[1/4] Carregando modelo e artefatos...")
    clf = joblib.load(MODELS_DIR / "random_forest.joblib")
    X = sp.load_npz(str(PROCESSED_DIR / "X.npz"))
    y_df = pd.read_csv(PROCESSED_DIR / "y.csv", index_col=0)

    # Usar label_num (0=sqli, 1=xss, 2=benign)
    if "label_num" not in y_df.columns:
        raise ValueError("Coluna 'label_num' não encontrada. Re-execute o estágio 3.")
    y = y_df["label_num"].values.astype(int)

    val_idx = np.load(PROCESSED_DIR / "indices_val.npy")

    df_curated = pd.read_csv(INTERIM_DIR / "02_curated.csv", dtype=str)
    df_curated["payload"] = df_curated["payload"].fillna("")
    df_curated["source"]  = df_curated["source"].fillna("unknown")

    print(f"  Total amostras: {X.shape[0]:,}")
    print(f"  Amostras de validação: {len(val_idx):,}")

    # Reconstruir X_val e y_val
    print("\n[2/4] Reconstruindo conjunto de validação...")
    X_val = X[val_idx]
    y_val = y[val_idx]

    # Fontes e payloads originais
    sources_val  = df_curated["source"].values[val_idx]  if len(df_curated) > max(val_idx) else np.array(["unknown"] * len(val_idx))
    payloads_val = df_curated["payload"].values[val_idx] if len(df_curated) > max(val_idx) else np.array([""] * len(val_idx))

    print("  Distribuição no val:")
    for num, txt in LABEL_MAP_INV.items():
        cnt = (y_val == num).sum()
        print(f"    {num} ({txt:6s}): {cnt:,}")

    # Predição
    print("\n[3/4] Realizando predições...")
    y_pred  = clf.predict(X_val)
    y_proba = clf.predict_proba(X_val)
    class_order = list(clf.classes_)  # ex: [0, 1, 2]

    # Mapear índices de probabilidade para posições fixas
    idx_sqli   = class_order.index(0) if 0 in class_order else 0
    idx_xss    = class_order.index(1) if 1 in class_order else 1
    idx_benign = class_order.index(2) if 2 in class_order else 2

    # Isolar falsos positivos: label real = 2 (benign), predito != 2
    fp_mask = (y_val == 2) & (y_pred != 2)
    n_fp = fp_mask.sum()
    n_benign_total = (y_val == 2).sum()

    fpr = n_fp / n_benign_total if n_benign_total > 0 else 0.0

    print(f"\n  Benign (2) no val   : {n_benign_total:,}")
    print(f"  Falsos Positivos    : {n_fp:,}")
    print(f"  FPR calculado       : {fpr:.6f}  ({fpr*100:.4f}%)")

    # Montar DataFrame de FPs
    print("\n[4/4] Gerando relatório de FPs...")
    fp_indices = np.where(fp_mask)[0]

    fp_records = []
    for i in fp_indices:
        proba_row = y_proba[i]
        pred_num  = int(y_pred[i])
        fp_records.append({
            "payload":       payloads_val[i],
            "label":         2,                            # benign = 2
            "label_str":     "benign",
            "predicted":     pred_num,
            "predicted_str": LABEL_MAP_INV.get(pred_num, str(pred_num)),
            "proba_benign":  float(proba_row[idx_benign]),
            "proba_sqli":    float(proba_row[idx_sqli]),
            "proba_xss":     float(proba_row[idx_xss]),
            "source":        sources_val[i],
        })

    df_fp = pd.DataFrame(fp_records)

    if df_fp.empty:
        print("  Nenhum falso positivo encontrado!")
        df_fp = pd.DataFrame(columns=[
            "payload", "label", "label_str", "predicted", "predicted_str",
            "proba_benign", "proba_sqli", "proba_xss", "source", "fp_group"
        ])
    else:
        df_fp["fp_group"] = df_fp["payload"].apply(classify_fp_group)

        df_fp["max_attack_proba"] = df_fp[["proba_sqli", "proba_xss"]].max(axis=1)
        df_fp = df_fp.sort_values("max_attack_proba", ascending=False).drop(
            columns=["max_attack_proba"]
        )

        # Top 30 FPs
        print(f"\n  Top 30 FPs (ordenados por confiança de ataque):")
        print(f"  {'payload[:60]':<60s}  {'pred':>6s}  {'proba_atk':>10s}  grupo")
        print("  " + "-" * 100)
        for _, row in df_fp.head(30).iterrows():
            payload_short = str(row["payload"])[:60]
            max_proba = max(row["proba_sqli"], row["proba_xss"])
            print(f"  {payload_short:<60s}  {row['predicted_str']:>6s}  {max_proba:>10.4f}  {row['fp_group']}")

        # Contagem por grupo
        print("\n  Contagem de FPs por grupo:")
        group_counts = df_fp["fp_group"].value_counts()
        for group, cnt in group_counts.items():
            print(f"    {group:30s}: {cnt:,}")

        # Sugestões
        print(suggest_templates(group_counts))

    # Salvar relatório
    fp_path = REPORTS_DIR / "false_positives.csv"
    df_fp.to_csv(fp_path, index=False)
    print(f"\n[SALVO] {fp_path}  ({len(df_fp):,} falsos positivos)")

    print("\n[OK] Estágio 5 concluído.")


if __name__ == "__main__":
    main()
