# WAF Dataset Pipeline — Detecção de Ataques Web com IA

Pipeline completo para construção, processamento e treinamento de um modelo **Random Forest** capaz de classificar requisições HTTP como `benign`, `sqli` ou `xss`.

**Versão atual do dataset: v2** — veja [DATASET_DOC_v2.md](DATASET_DOC_v2.md) para documentação completa.

---

## Resultados do Modelo (v2)

| Métrica | Target | Resultado | Status |
|---------|--------|-----------|--------|
| Recall SQLi | ≥ 95% | **99.43%** | ✅ |
| Recall XSS | ≥ 95% | **99.86%** | ✅ |
| Falsos Positivos (FPR) | ≤ 0.5% | **0.43%** | ✅ |
| F1 Macro | ≥ 95% | **99.48%** | ✅ |
| Latência p95 | ≤ 50ms | **78.7ms** | ⚠️ acima do alvo* |

> \* Latência medida em CPU com `n_jobs=2`. Redutível com menos estimadores sem impacto relevante nas métricas de qualidade.

> Dataset: **708.625 amostras** (pós-curadoria) — 70% treino / 15% validação / 15% teste.

---

## Classes

| Rótulo | Numérico | Descrição |
|--------|----------|-----------|
| `sqli` | `0` | SQL Injection |
| `xss` | `1` | Cross-Site Scripting |
| `benign` | `2` | Tráfego legítimo |

---

## Estrutura do Projeto

```
dataset_pipeline/
├── 01_collect.py          # Coleta e geração de dados brutos
├── 02_curate.py           # Curadoria, normalização e variantes ofuscadas
├── 03_features.py         # Extração de features (TF-IDF + features manuais)
├── 04_train_validate.py   # Treino do Random Forest + cross-validation
├── 05_fp_analysis.py      # Análise de falsos positivos
├── 06_export_dataset.py   # Exportação do dataset final em CSV
├── requirements.txt
├── DATASET_DOC_v2.md      # Documentação completa do dataset (v2)
│
├── data/
│   ├── raw/               # Datasets de origem (não versionados — veja abaixo)
│   │   └── seclists/      # Clone sparse do SecLists (não versionado)
│   ├── interim/           # Dados intermediários gerados (não versionados)
│   └── processed/         # Features e splits finais (não versionados)
│
├── models/                # Modelos treinados (Git LFS — veja abaixo)
└── reports/               # Métricas e análise de falsos positivos
    ├── metrics_test.json
    └── false_positives.csv
```

---

## Pré-requisitos

- Python 3.10 ou superior
- ~6 GB de RAM disponível durante o treino
- ~3 GB de espaço em disco para os dados intermediários e modelo

```bash
pip install -r requirements.txt
```

---

## Reprodução do Treinamento do Zero

Para reproduzir o treinamento completo a partir dos dados originais, siga os passos abaixo **em ordem**.

### Passo 1 — Obter os datasets de origem

Os arquivos raw **não estão versionados** no repositório (licença Kaggle proíbe redistribuição; CSIC 2010 requer cadastro). Baixe-os manualmente e coloque em `data/raw/`:

| Arquivo esperado | Fonte | Link |
|-----------------|-------|------|
| `data/raw/sqli_biggest.csv` | Kaggle — gambleryu | [biggest-sql-injection-dataset](https://www.kaggle.com/datasets/gambleryu/biggest-sql-injection-dataset) |
| `data/raw/sqli_dataset.csv` | Kaggle — sajid576 | [sql-injection-dataset](https://www.kaggle.com/datasets/sajid576/sql-injection-dataset) |
| `data/raw/xss_dataset.csv` | Kaggle — syedsaqlainhussain | [cross-site-scripting-xss-dataset-for-deep-learning](https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning) |
| `data/raw/normalTrafficTraining.txt` | CSIC 2010 HTTP Dataset | [gitlab.fing.edu.uy](https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/blob/master/csic_2010/) |
| `data/raw/normalTrafficTest.txt` | CSIC 2010 HTTP Dataset | [gitlab.fing.edu.uy](https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/blob/master/csic_2010/) |
| `data/raw/anomalousTrafficTest.txt` | CSIC 2010 HTTP Dataset | [gitlab.fing.edu.uy](https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/blob/master/csic_2010/) |

### Passo 2 — Clonar o SecLists (sparse checkout)

O SecLists é clonado diretamente em `data/raw/seclists/` usando sparse checkout para baixar apenas as pastas de XSS e SQLi (~20 MB em vez do repositório completo de ~1 GB):

```bash
cd data/raw
git clone --depth=1 --filter=blob:none --sparse https://github.com/danielmiessler/SecLists seclists
cd seclists
git sparse-checkout set "Fuzzing/XSS" "Fuzzing/Databases/SQLi"
cd ../../..
```

### Passo 3 — Instalar dependências

```bash
pip install -r requirements.txt
```

### Passo 4 — Executar o pipeline

Execute os estágios em ordem. **Tempo estimado total: 2–3 horas** (o estágio 4 é o mais longo).

```bash
# Estágio 1 — Coleta (~2 min)
# Lê data/raw/, gera data/interim/01_raw_combined.csv (~649k amostras)
python 01_collect.py

# Estágio 2 — Curadoria (~5 min)
# Limpeza, dedup, variantes ofuscadas
# Saída: data/interim/02_curated.csv (~708k amostras)
python 02_curate.py

# Estágio 3 — Features (~15 min, uso intenso de RAM)
# TF-IDF word (8k) + char (12k) + 15 features manuais = 20.015 dims
# Saída: data/processed/X.npz (~1 GB), data/processed/y.csv
#        models/word_tfidf.joblib, models/char_tfidf.joblib
#        models/manual_scaler.joblib, models/feature_scaler.joblib
python 03_features.py

# Estágio 4 — Treino (~90 min com n_jobs=2, mais rápido com mais CPUs)
# Random Forest 300 árvores + cross-validation k=3
# Saída: models/random_forest.joblib, reports/metrics_test.json
python 04_train_validate.py

# Estágio 5 — Análise de falsos positivos (~2 min)
# Saída: reports/false_positives.csv
python 05_fp_analysis.py

# Estágio 6 — Exportação (~3 min)
# Saída: data/processed/dataset_{train,val,test}.csv
python 06_export_dataset.py
```

> **Windows:** todos os comandos acima funcionam no PowerShell ou CMD. Não há dependência de bash.

### Usando o modelo treinado sem reprocessar

Se o repositório já inclui os arquivos em `models/` via Git LFS, o `waf_app` funciona diretamente sem rodar o pipeline. Basta:

```bash
cd ../waf_app
pip install -r requirements.txt   # se ainda não instalou
python interactive_test.py         # teste interativo via CLI
# ou
uvicorn app:app --reload           # API FastAPI em http://localhost:8000
```

---

## Fontes de Dados (v2)

| Fonte | Tipo | Classe | Amostras |
|-------|------|--------|----------|
| Kaggle — sqli_biggest | Real | sqli | 148.326 |
| Kaggle — sqli_dataset | Real | sqli | 30.919 |
| CSIC 2010 anomalous | Real | sqli | 25.065 |
| Kaggle — xss_dataset | Real | xss | 13.686 |
| CSIC 2010 normal | Real | benign | 72.000 |
| Geração sintética (Faker, 180 templates) | Sintético | benign | 150.000 |
| Augmentação XSS (12 categorias documentadas) | Sintético | xss | 200.000 |
| SecLists XSS (20 arquivos, dedup) | Real | xss | 9.868 |
| SecLists SQLi (9 arquivos, dedup) | Real | sqli | 479 |
| **Total pós-coleta** | | | **649.653** |

---

## Features Extraídas (Estágio 3)

| Grupo | Dimensões | Descrição |
|-------|-----------|-----------|
| Word TF-IDF | 8.000 | Unigramas e bigramas de palavras, `sublinear_tf=True` |
| Char TF-IDF | 12.000 | Char n-grams (3–5), `analyzer="char_wb"` |
| Features manuais | 15 | Contagens de símbolos, keywords SQL/XSS, padrões regex |
| **Total** | **20.015** | Matriz esparsa CSR, normalizada com `MaxAbsScaler` |

---

## Saídas do Pipeline

| Arquivo | Conteúdo |
|---------|----------|
| `models/random_forest.joblib` | Modelo treinado (227 MB) |
| `models/word_tfidf.joblib` | Vetorizador Word TF-IDF |
| `models/char_tfidf.joblib` | Vetorizador Char TF-IDF |
| `models/feature_scaler.joblib` | Scaler global (MaxAbsScaler) |
| `models/manual_scaler.joblib` | Scaler das features manuais |
| `reports/metrics_test.json` | Métricas completas no conjunto de teste |
| `reports/false_positives.csv` | Amostras benignas classificadas incorretamente |
| `data/processed/dataset_{train,val,test}.csv` | Splits finais |

---

## Documentação Adicional

- [DATASET_DOC_v2.md](DATASET_DOC_v2.md) — Documentação completa: fontes, pipeline, features, métricas, análise de falsos positivos e limitações conhecidas
