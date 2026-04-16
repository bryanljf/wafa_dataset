"""
Estágio 2 — Curadoria, normalização e geração de variantes ofuscadas.
Lê:   data/interim/01_raw_combined.csv
Saída: data/interim/02_curated.csv
"""

import random
import re
import warnings
from pathlib import Path
from urllib.parse import unquote_plus

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

BASE_DIR = Path(__file__).parent
INTERIM_DIR = BASE_DIR / "data" / "interim"
INPUT_FILE = INTERIM_DIR / "01_raw_combined.csv"
OUTPUT_FILE = INTERIM_DIR / "02_curated.csv"

# Caracteres zero-width e similares a remover
ZERO_WIDTH = re.compile(r"[\u200b\u200c\u200d\ufeff\u00ad\u2060]")


# ---------------------------------------------------------------------------
# Limpeza mínima e intencional
# ---------------------------------------------------------------------------

def clean_payload(text: str) -> str:
    """
    Normalização MÍNIMA para não apagar sinais de ataque nem casos legítimos ambíguos.
    NÃO lowercasa, NÃO remove apóstrofes, NÃO remove símbolos.
    """
    # Decodificar percent-encoding (%27 → ', %3C → <, %20 → espaço, etc.)
    try:
        text = unquote_plus(text)
    except Exception:
        pass

    # Remover caracteres zero-width
    text = ZERO_WIDTH.sub("", text)

    # Normalizar espaços múltiplos para um único espaço
    text = re.sub(r" {2,}", " ", text)

    return text.strip()


# ---------------------------------------------------------------------------
# Geração de variantes ofuscadas
# ---------------------------------------------------------------------------

def obfuscate_sqli(payload: str) -> list[str]:
    """Gera variantes de ofuscação para payloads SQLi."""
    variants = [
        payload.upper(),
        payload.lower(),
        payload.replace(" ", "/**/"),
        payload.replace(" ", "\t"),
        payload.replace("'", "%27").replace(" ", "%20"),
        payload.replace("'", "%2527"),           # double URL-encode
        payload + " -- -",
        payload + " #",
    ]
    # Filtrar idênticos ao original
    return [v for v in variants if v != payload]


def obfuscate_xss(payload: str) -> list[str]:
    """Gera variantes de ofuscação para payloads XSS."""
    variants = []

    # <script> → <SCRIPT>
    v = re.sub(r"<script", "<SCRIPT", payload, flags=re.IGNORECASE)
    variants.append(v)

    # <script> → <scr\x00ipt> (null byte)
    v = re.sub(r"<script", "<scr\x00ipt", payload, flags=re.IGNORECASE)
    variants.append(v)

    # alert → al\u0065rt (unicode escape)
    v = payload.replace("alert", "al\u0065rt")
    variants.append(v)

    # <script>alert(1)</script> → <img src=x onerror=alert(1)>
    v = re.sub(
        r"<script[^>]*>alert\((\d+)\)</script>",
        r"<img src=x onerror=alert(\1)>",
        payload,
        flags=re.IGNORECASE,
    )
    variants.append(v)

    # javascript: → JaVaScRiPt:
    v = re.sub(r"javascript:", "JaVaScRiPt:", payload, flags=re.IGNORECASE)
    variants.append(v)

    # Adicionar atributo inócuo antes do payload
    v = re.sub(r"<(script|img|svg|body)", r'<div id="x"><\1', payload, flags=re.IGNORECASE)
    variants.append(v)

    # Filtrar idênticos ao original
    return [v for v in variants if v != payload]


def generate_variants(df: pd.DataFrame, sample_frac: float = 0.4) -> pd.DataFrame:
    """
    Para 40% das amostras maliciosas, gera variantes ofuscadas.
    Retorna DataFrame com as variantes (source += '_obfuscated').
    """
    malicious = df[df["label"].isin(["sqli", "xss"])].copy()
    sampled = malicious.sample(frac=sample_frac, random_state=SEED)

    new_rows = []
    for _, row in sampled.iterrows():
        payload = row["payload"]
        label = row["label"]

        if label == "sqli":
            variants = obfuscate_sqli(payload)
        else:
            variants = obfuscate_xss(payload)

        for v in variants:
            new_rows.append({
                "payload": v,
                "label": label,
                "source": str(row["source"]) + "_obfuscated",
            })

    return pd.DataFrame(new_rows)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("ESTÁGIO 2 — Curadoria e geração de variantes")
    print("=" * 60)

    if not INPUT_FILE.exists():
        raise FileNotFoundError(f"Arquivo de entrada não encontrado: {INPUT_FILE}")

    df = pd.read_csv(INPUT_FILE, dtype=str)
    df["payload"] = df["payload"].fillna("")
    df["label"] = df["label"].fillna("")
    df["source"] = df["source"].fillna("unknown")

    print(f"\n[ANTES] Total de linhas: {len(df):,}")
    print("Distribuição por label (antes):")
    for label, cnt in df["label"].value_counts().items():
        print(f"  {label:10s}: {cnt:7,d}")

    # --- Limpeza ---
    print("\n[LIMPEZA] Aplicando normalização mínima...")
    df["payload"] = df["payload"].apply(clean_payload)

    # Remover payloads vazios ou muito curtos
    antes = len(df)
    df = df[df["payload"].str.len() >= 4]
    print(f"  Removidos por comprimento < 4: {antes - len(df):,}")

    # Remover duplicatas exatas após limpeza
    antes = len(df)
    df = df.drop_duplicates(subset=["payload", "label"])
    print(f"  Duplicatas removidas: {antes - len(df):,}")

    # --- Variantes ofuscadas ---
    print("\n[OBFUSCATION] Gerando variantes para 20% dos maliciosos...")
    df_variants = generate_variants(df, sample_frac=0.2)
    print(f"  Variantes geradas: {len(df_variants):,}")

    # Concatenar e deduplicar novamente
    df = pd.concat([df, df_variants], ignore_index=True)
    antes = len(df)
    df = df.drop_duplicates(subset=["payload", "label"])
    removidas_extra = antes - len(df)
    if removidas_extra > 0:
        print(f"  Duplicatas adicionais removidas após variantes: {removidas_extra:,}")

    # --- Relatório final ---
    print(f"\n[DEPOIS] Total de linhas: {len(df):,}")
    print("Distribuição por label (depois):")
    counts = df["label"].value_counts()
    total = len(df)
    for label, cnt in counts.items():
        print(f"  {label:10s}: {cnt:7,d}  ({cnt/total*100:.1f}%)")

    # Salvar
    df.to_csv(OUTPUT_FILE, index=False)
    size_kb = OUTPUT_FILE.stat().st_size / 1024
    print(f"\n[SALVO] {OUTPUT_FILE}  ({total:,} linhas, {size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
