# WAF Dataset Pipeline — Detecção de Ataques Web com IA

Pipeline completo para construção, processamento e treinamento de um modelo **Random Forest** capaz de classificar requisições HTTP como `benign`, `sqli` ou `xss`. Desenvolvido como parte de TCC de Segurança da Informação.

---

## Resultados do Modelo

| Métrica | Target | Resultado | Status |
|---------|--------|-----------|--------|
| Recall SQLi | ≥ 95% | **99.52%** | ✅ |
| Recall XSS | ≥ 95% | **99.70%** | ✅ |
| Falsos Positivos (FPR) | ≤ 0.5% | **0.26%** | ✅ |
| F1 Macro | ≥ 95% | **99.48%** | ✅ |
| Latência p95 | ≤ 50ms | **57.29ms** | ⚠️ aceitável |

> Dataset: **464.700 amostras** — 70% treino / 15% validação / 15% teste.

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
├── wafahell_integration.py # Integração com WAF
├── requirements.txt
├── run_pipeline.sh        # Script para rodar todo o pipeline de uma vez
│
├── data/
│   ├── raw/               # Datasets de origem (não versionados — veja abaixo)
│   ├── interim/           # Dados intermediários gerados (não versionados)
│   └── processed/         # Features e splits finais (não versionados)
│
├── models/                # Modelos treinados (não versionados)
└── reports/               # Métricas e análise de falsos positivos
    ├── metrics_test.json
    └── false_positives.csv
```

---

## Pré-requisitos

- Python 3.10 ou superior
- ~4 GB de RAM disponível (para o dataset completo)

```bash
pip install -r requirements.txt
```

Dependências principais:

```
pandas==2.2.2
numpy==1.26.4
scikit-learn==1.5.0
scipy==1.13.1
faker==25.2.0
joblib==1.4.2
imbalanced-learn==0.12.3
```

---

## Dados de Origem (obtidos separadamente)

Os arquivos de dados **não estão versionados** no repositório por serem muito grandes. Coloque-os em `data/raw/` antes de rodar o pipeline:

| Arquivo | Fonte | Download |
|---------|-------|----------|
| `sqli_biggest.csv` | Kaggle — gambleryu | [Link](https://www.kaggle.com/datasets/gambleryu/biggest-sql-injection-dataset) |
| `sqli_dataset.csv` | Kaggle — sajid576 | [Link](https://www.kaggle.com/datasets/sajid576/sql-injection-dataset) |
| `xss_dataset.csv` | Kaggle — syedsaqlainhussain | [Link](https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning) |
| `normalTrafficTraining.txt` | CSIC 2010 HTTP Dataset | [Link](https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/blob/master/csic_2010/) |
| `normalTrafficTest.txt` | CSIC 2010 HTTP Dataset | [Link](https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/blob/master/csic_2010/) |
| `anomalousTrafficTest.txt` | CSIC 2010 HTTP Dataset | [Link](https://gitlab.fing.edu.uy/gsi/web-application-attacks-datasets/-/blob/master/csic_2010/) |

> Os arquivos do CSIC 2010 também estão disponíveis no arquivo `datasets.txt` com os links de referência.

---

## Como Rodar o Pipeline

### Opção 1 — Script completo (Linux/macOS)

```bash
chmod +x run_pipeline.sh
./run_pipeline.sh
```

### Opção 2 — Passo a passo (Windows ou qualquer OS)

Execute os scripts em ordem:

```bash
# 1. Coleta: lê data/raw/ e gera data/interim/01_raw_combined.csv
python 01_collect.py

# 2. Curadoria: normaliza payloads, remove duplicatas, gera variantes
#    Entrada: data/interim/01_raw_combined.csv
#    Saída:   data/interim/02_curated.csv
python 02_curate.py

# 3. Features: extrai TF-IDF (word + char) + 15 features manuais
#    Saída: data/processed/X.npz, data/processed/y.csv
#           models/word_tfidf.joblib, models/char_tfidf.joblib
#           models/manual_scaler.joblib, models/feature_scaler.joblib
python 03_features.py

# 4. Treino: Random Forest (300 árvores) + cross-validation (k=3)
#    Saída: models/random_forest.joblib, reports/metrics_test.json
#           data/processed/indices_{train,val,test}.npy
python 04_train_validate.py

# 5. Análise de falsos positivos no conjunto de validação
#    Saída: reports/false_positives.csv
python 05_fp_analysis.py

# 6. Exportação dos splits finais em CSV com todas as features
#    Saída: data/processed/dataset_{train,val,test}.csv
python 06_export_dataset.py
```

---

## Features Extraídas (Estágio 3)

O modelo utiliza **features híbridas** — representações textuais + features de engenharia manual:

| Grupo | Descrição |
|-------|-----------|
| **Word TF-IDF** | Vetorização por tokens (n-gram 1-2), top 50.000 features |
| **Char TF-IDF** | Vetorização por caracteres (n-gram 2-5), top 30.000 features |
| **Comprimento** | `len(payload)` normalizado |
| **Contagens de símbolos** | `'`, `"`, `<`, `>`, `;`, `(`, `%`, `--`, `/*` |
| **Keywords SQL** | Contagem de: SELECT, UNION, INSERT, DROP, UPDATE, DELETE, WHERE... |
| **Keywords XSS** | Contagem de: `<script`, `javascript:`, `onerror`, `onload`... |
| **Padrões regex** | `\d+=\d+` (1=1), `<script`, event handlers `on*=` |

---

## Fontes de Dados

O dataset foi construído com foco em **minimizar a taxa de falsos positivos**, combinando:

- **148.326** payloads SQLi — Kaggle (gambleryu)
- **30.919** payloads SQLi — Kaggle (sajid576)
- **13.686** payloads XSS — Kaggle (syedsaqlainhussain)
- **97.065** requisições reais — CSIC 2010 (benign + anomalous)
- **100.000** requisições sintéticas — geradas com Faker `pt_BR` (seed=42), cobrindo 66 padrões que causam falsos positivos em WAFs tradicionais

---

## Saídas do Pipeline

Após rodar todos os estágios:

| Arquivo | Conteúdo |
|---------|----------|
| `models/random_forest.joblib` | Modelo treinado |
| `models/word_tfidf.joblib` | Vetorizador Word TF-IDF |
| `models/char_tfidf.joblib` | Vetorizador Char TF-IDF |
| `models/feature_scaler.joblib` | Scaler de features combinadas |
| `models/manual_scaler.joblib` | Scaler de features manuais |
| `reports/metrics_test.json` | Métricas completas no conjunto de teste |
| `reports/false_positives.csv` | Amostras benignas classificadas incorretamente |
| `data/processed/dataset_train.csv` | Split de treino com payload + features |
| `data/processed/dataset_val.csv` | Split de validação |
| `data/processed/dataset_test.csv` | Split de teste |

---

## Documentação Adicional

- [DATASET_DOC.md](DATASET_DOC.md) — Documentação completa das fontes de dados, processo de curadoria e design decisions
- [MODEL_RESULTS.md](MODEL_RESULTS.md) — Resultados detalhados: cross-validation, matriz de confusão, análise de falsos positivos
