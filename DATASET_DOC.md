# Dataset de Detecção de Ataques Web (SQLi e XSS)
**Objetivo:** Treinar um modelo Random Forest capaz de classificar requisições HTTP como `benign`, `sqli` ou `xss` com alta precisão e baixo índice de falsos positivos.

---

## 1. Visão Geral

O dataset foi construído a partir de **três fontes distintas**: datasets públicos de ataques (Kaggle), tráfego HTTP real capturado (CSIC 2010), e geração sintética de tráfego legítimo ambíguo. O objetivo do design foi especificamente minimizar a **Taxa de Falsos Positivos (FPR)**, garantindo que requisições legítimas não sejam bloqueadas indevidamente pelo WAF.

### Mapeamento de Classes

| Rótulo Textual | Rótulo Numérico | Descrição |
|---------------|----------------|-----------|
| `sqli` | `0` | SQL Injection — consultas maliciosas explorando banco de dados |
| `xss` | `1` | Cross-Site Scripting — payloads injetando código JavaScript |
| `benign` | `2` | Tráfego legítimo — requisições normais de usuários |

---

## 2. Fontes de Dados

### 2.1 Datasets Kaggle — Ataques SQLi

#### sqli_biggest.csv
- **Origem:** [Biggest SQL Injection Dataset — Kaggle (GAMBLER YU)](https://www.kaggle.com/datasets/gambleryu/biggest-sql-injection-dataset)
- **Coluna utilizada:** `Query`
- **Classe:** `sqli` (0)
- **Amostras carregadas:** 148.326
- **Conteúdo:** Consultas SQL maliciosas de múltiplos tipos de injeção — UNION-based, boolean-based, error-based, time-based blind.

#### sqli_dataset.csv
- **Origem:** [SQL Injection Dataset — Kaggle (sajid576)](https://www.kaggle.com/datasets/sajid576/sql-injection-dataset) — arquivo `Modified_SQL_Dataset.csv`, renomeado
- **Coluna utilizada:** `Query`
- **Classe:** `sqli` (0)
- **Amostras carregadas:** 30.919
- **Conteúdo:** Versão modificada/ampliada com consultas SQL maliciosas e legítimas misturadas, com rótulo binário.

### 2.2 Datasets Kaggle — Ataques XSS

#### xss_dataset.csv
- **Origem:** [Cross Site Scripting XSS Dataset for Deep Learning — Kaggle (syedsaqlainhussain)](https://www.kaggle.com/datasets/syedsaqlainhussain/cross-site-scripting-xss-dataset-for-deep-learning)
- **Coluna utilizada:** `Sentence`
- **Classe:** `xss` (1)
- **Amostras carregadas:** 13.686
- **Conteúdo:** Payloads de XSS incluindo variantes de `<script>`, event handlers, `javascript:` URIs, encoded payloads.

### 2.3 CSIC 2010 HTTP Dataset — Tráfego Real

- **Origem:** [CSIC 2010 HTTP Dataset](http://www.isi.csic.es/dataset/) — Instituto de Seguridad de la Información (CSIC), Madrid
- **Formato:** Blocos de requisições HTTP brutas (GET e POST), separados por linhas em branco
- **Extração:** Path + query string da linha de request, concatenado com o body (quando presente via `Content-Length`)

| Arquivo | Classe | Amostras |
|---------|--------|---------|
| `normalTrafficTraining.txt` | `benign` (2) | 36.000 |
| `normalTrafficTest.txt` | `benign` (2) | 36.000 |
| `anomalousTrafficTest.txt` | `sqli` (0) | 25.065 |

**Notas:**
- O tráfego benign do CSIC contém requisições HTTP reais para uma aplicação de e-commerce (catálogo de produtos, formulários, autenticação)
- Alta taxa de duplicatas (~50%) foi esperada e tratada na fase de curadoria

### 2.4 Geração Sintética — Tráfego Legítimo Ambíguo

- **Ferramenta:** [Faker](https://faker.readthedocs.io/) com locale `pt_BR`
- **Classe:** `benign` (2)
- **Amostras geradas:** 100.000
- **Seed:** 42 (reprodutível)

Esta é a fonte mais crítica para controle do FPR. Gerada com **66 templates distintos** cobrindo padrões que tipicamente causam falsos positivos em sistemas WAF:

| Padrão | Exemplo |
|--------|---------|
| Apóstrofes em nomes próprios | `nome=O'Brien&acao=buscar` |
| Palavras SQL em contexto legítimo | `q=como+usar+SELECT+em+banco` |
| HTML legítimo (CMS/editor) | `conteudo=<p>Texto normal</p>` |
| Palavra "script" sem tag HTML | `arquivo=main_script.js` |
| Parâmetros booleanos ambíguos | `union=true&select_all=false` |
| Event handlers em config | `onload=false&onerror=retry` |
| Encoding normal em URLs | `/busca?q=produto%20nome` |
| Campos de senha/token | `usuario=joao&senha=***` |
| Comentários com pontuação | `comentario=Texto, com vírgulas.` |
| Paths de API REST | `/api/v1/usuarios/123/perfil` |
| Dados de e-commerce | `sku=AB-1234&preco=99.90` |
| Termos técnicos inocentes | `exec=concluido&job_id=abc123` |

---

## 3. Pipeline de Processamento

O dataset passou por **6 estágios sequenciais**, cada um lendo a saída do anterior:

```
data/raw/  →  01_collect  →  02_curate  →  03_features  →  04_train  →  05_export
```

### Estágio 1 — Coleta (`01_collect.py`)

- Carregamento dos arquivos Kaggle com fallback de encoding (UTF-8 → Latin-1)
- Parser de blocos HTTP para o CSIC 2010
- Geração de 100.000 amostras sintéticas legítimas com Faker
- **Saída:** `data/interim/01_raw_combined.csv` (colunas: `payload`, `label`, `source`)

**Distribuição pós-coleta:**

| Classe | Amostras | % |
|--------|---------|---|
| sqli | 203.805 | 52,3% |
| benign | 172.000 | 44,2% |
| xss | 13.565 | 3,5% |
| **Total** | **389.370** | |

### Estágio 2 — Curadoria (`02_curate.py`)

**Limpeza aplicada:**
- Decodificação de percent-encoding (`%27` → `'`, `%3C` → `<`, `%20` → espaço) via `urllib.parse.unquote_plus`
- Remoção de caracteres zero-width (U+200B, U+FEFF, etc.)
- Normalização de espaços múltiplos
- Remoção de payloads com comprimento < 4 caracteres
- Remoção de duplicatas exatas após limpeza

> **Normalização mínima e intencional:** apóstrofes, símbolos e maiúsculas/minúsculas foram preservados — esses são sinais discriminativos que o modelo precisa aprender.

**Geração de variantes ofuscadas (20% dos maliciosos):**

Para aumentar o recall contra técnicas de evasão, foram geradas variantes ofuscadas de 20% das amostras maliciosas:

*SQLi:*
- UPPERCASE / lowercase completo
- Substituição de espaço por `/**/` (comentário inline SQL)
- Substituição de espaço por `\t`
- URL-encode de `'` → `%27` e espaço → `%20`
- Double URL-encode: `'` → `%2527`
- Adição de comentário SQL: `-- -` ou `#`

*XSS:*
- `<script>` → `<SCRIPT>`
- `<script>` → `<scr\x00ipt>` (null byte)
- `alert` → `al\u0065rt` (unicode escape)
- Substituição por `<img src=x onerror=alert(1)>`
- `javascript:` → `JaVaScRiPt:`
- Adição de atributos inócuos antes do payload

**Distribuição pós-curadoria:**

| Classe | Amostras | % |
|--------|---------|---|
| sqli | 365.156 | 78,6% |
| benign | 88.565 | 19,1% |
| xss | 10.979 | 2,4% |
| **Total** | **464.700** | |

> A redução de benign (172k → 88k) ocorreu por alta taxa de duplicação no CSIC — requisições HTTP repetidas para os mesmos endpoints são naturais em tráfego de teste.

### Estágio 3 — Extração de Features (`03_features.py`)

Cada payload foi transformado em um vetor de features combinando três tipos:

#### TF-IDF Word N-grams
```
analyzer    = "word"
ngram_range = (1, 2)       — unigramas e bigramas
max_features = 8.000
sublinear_tf = True        — log(1 + tf) para suavizar frequência
min_df      = 2
token_pattern = r"(?u)\b\w+\b|[<>'\";()%=]"  — captura símbolos como tokens
```

#### TF-IDF Char N-grams
```
analyzer    = "char_wb"
ngram_range = (3, 5)       — trigramas a pentagramas de caracteres
max_features = 12.000
sublinear_tf = True
min_df      = 3
```

#### Features Manuais Estruturais (15 features)

| # | Feature | Descrição |
|---|---------|-----------|
| 1 | `feat_len` | Comprimento total do payload |
| 2 | `feat_apostrophe` | Contagem de `'` |
| 3 | `feat_dquote` | Contagem de `"` |
| 4 | `feat_lt` | Contagem de `<` |
| 5 | `feat_gt` | Contagem de `>` |
| 6 | `feat_semicolon` | Contagem de `;` |
| 7 | `feat_paren` | Contagem de `(` |
| 8 | `feat_percent` | Contagem de `%` |
| 9 | `feat_dashdash` | Contagem de `--` |
| 10 | `feat_comment` | Contagem de `/*` |
| 11 | `feat_sql_kw` | Soma de keywords SQL presentes¹ |
| 12 | `feat_xss_kw` | Soma de keywords XSS presentes² |
| 13 | `feat_1eq1` | Padrão `\d+=\d+` presente (0/1) |
| 14 | `feat_script_tag` | Tag `<script` presente (0/1) |
| 15 | `feat_handler` | Event handler `on\w+=` presente (0/1) |

> ¹ Keywords SQL: `select, union, insert, drop, update, delete, where, having, exec, xp_, information_schema, sleep, benchmark, cast, convert`  
> ² Keywords XSS: `script, onerror, onload, alert, javascript, iframe, document., cookie, eval(, src=, href=, onclick`

**Normalização:**
- Features manuais: `MaxAbsScaler` individual antes da concatenação
- Matriz final completa: `MaxAbsScaler` global após concatenação

**Concatenação final:**
```
X = [X_word (8k) | X_char (12k) | X_manual (15)] = 20.015 features por amostra
Shape: (464.700, 20.015) — matriz esparsa (scipy CSR)
Densidade: 1,633%
```

### Estágio 4 — Treino e Validação (`04_train_validate.py`)

#### Divisão dos dados
```
Estratégia: StratifiedShuffleSplit (preserva proporção de classes)
Seed: 42

Treino:     70%  →  325.290 amostras
Validação:  15%  →   69.705 amostras
Teste:      15%  →   69.705 amostras
```

#### Balanceamento
O conjunto de **treino** foi balanceado com `RandomOverSampler` (imbalanced-learn), igualando as 3 classes por oversampling da minoria (XSS e benign):

| Classe | Antes | Depois |
|--------|-------|--------|
| sqli (0) | ~255k | ~255k |
| benign (2) | ~62k | ~255k |
| xss (1) | ~7k | ~255k |

> O oversampling é aplicado **somente no treino**. Validação e teste mantêm a distribuição real para avaliação honesta.

#### Modelo
```python
RandomForestClassifier(
    n_estimators    = 300,
    max_features    = "sqrt",
    class_weight    = "balanced_subsample",
    min_samples_leaf = 2,
    n_jobs          = 2,
    random_state    = 42,
)
```

#### Cross-Validation
```
Estratégia: StratifiedKFold, k=3
Cada fold: treina com oversampling, valida sem
```

---

## 4. Arquivos do Dataset Exportado

Os arquivos CSV foram exportados pelo estágio (`06_export_dataset.py`) e estão em `data/processed/`:

| Arquivo | Split | Amostras | Uso |
|---------|-------|---------|-----|
| `dataset_train.csv` | Treino | ~325k | Usado para treinar o modelo |
| `dataset_val.csv` | Validação | ~70k | Seleção de hiperparâmetros e análise de FP |
| `dataset_test.csv` | Teste | ~70k | Avaliação final das métricas |

### Colunas dos CSVs

| Coluna | Tipo | Descrição |
|--------|------|-----------|
| `index_original` | int | Índice da amostra no dataset completo (02_curated.csv) |
| `payload` | string | Texto da requisição HTTP |
| `label` | string | Classe: `sqli`, `xss` ou `benign` |
| `label_num` | int | Classe numérica: 0=sqli, 1=xss, 2=benign |
| `source` | string | Arquivo de origem (ex: `sqli_biggest.csv`, `synthetic_legit`) |
| `split` | string | `treino`, `validacao` ou `teste` |
| `feat_len` | int | Comprimento do payload |
| `feat_apostrophe` | int | Contagem de apóstrofes |
| `feat_dquote` | int | Contagem de aspas duplas |
| `feat_lt` | int | Contagem de `<` |
| `feat_gt` | int | Contagem de `>` |
| `feat_semicolon` | int | Contagem de `;` |
| `feat_paren` | int | Contagem de `(` |
| `feat_percent` | int | Contagem de `%` |
| `feat_dashdash` | int | Contagem de `--` |
| `feat_comment` | int | Contagem de `/*` |
| `feat_sql_kw` | int | Keywords SQL encontradas |
| `feat_xss_kw` | int | Keywords XSS encontradas |
| `feat_1eq1` | int | Padrão numérico `n=n` (0 ou 1) |
| `feat_script_tag` | int | Tag `<script` presente (0 ou 1) |
| `feat_handler` | int | Event handler `on*=` presente (0 ou 1) |

---

## 5. Critérios de Qualidade do Modelo

| Métrica | Threshold | Descrição |
|---------|-----------|-----------|
| Recall SQLi | ≥ 95% | Taxa de detecção de SQL Injection |
| Recall XSS | ≥ 95% | Taxa de detecção de Cross-Site Scripting |
| **FPR** | **≤ 0,5%** | **Taxa de falsos positivos sobre tráfego benign** |
| F1 Macro | ≥ 95% | Equilíbrio entre precisão e recall |
| Latência p95 | ≤ 50ms | Inferência por requisição (middleware em produção) |

> O **FPR ≤ 0,5%** é o critério mais crítico: um WAF que bloqueia tráfego legítimo frequentemente é inutilizável em produção.

---

## 6. Reprodutibilidade

Todos os processos aleatórios utilizam **seed fixo 42**:
- `random.seed(42)`
- `numpy.random.seed(42)`
- `Faker.seed(42)`
- `StratifiedShuffleSplit(random_state=42)`
- `RandomOverSampler(random_state=42)`
- `RandomForestClassifier(random_state=42)`

Para reproduzir o dataset do zero:

```bash
cd dataset_pipeline
pip install -r requirements.txt

# Colocar os arquivos externos em data/raw/

python 01_collect.py
python 02_curate.py
python 03_features.py
python 04_train_validate.py
python 05_fp_analysis.py
python 06_export_dataset.py
```

---

## 7. Dependências

| Biblioteca | Versão | Uso |
|-----------|--------|-----|
| pandas | 2.2.2 | Manipulação de dados |
| numpy | 1.26.4 | Operações numéricas |
| scikit-learn | 1.5.0 | TF-IDF, Random Forest, métricas |
| scipy | 1.13.1 | Matrizes esparsas |
| faker | 25.2.0 | Geração de tráfego sintético |
| joblib | 1.4.2 | Serialização de modelos |
| imbalanced-learn | 0.12.3 | Balanceamento com oversampling |

---

## 8. Estrutura de Arquivos

```
dataset_pipeline/
├── data/
│   ├── raw/                         ← Fontes externas (não versionadas)
│   │   ├── sqli_biggest.csv
│   │   ├── sqli_dataset.csv
│   │   ├── xss_dataset.csv
│   │   ├── normalTrafficTraining.txt
│   │   ├── normalTrafficTest.txt
│   │   └── anomalousTrafficTest.txt
│   ├── interim/
│   │   ├── 01_raw_combined.csv      ← Saída do estágio 1
│   │   └── 02_curated.csv           ← Saída do estágio 2
│   └── processed/
│       ├── X.npz                    ← Matriz de features (esparsa)
│       ├── y.csv                    ← Labels (texto + numérico)
│       ├── indices_train.npy        ← Índices do split de treino
│       ├── indices_val.npy          ← Índices do split de validação
│       ├── indices_test.npy         ← Índices do split de teste
│       ├── dataset_train.csv        ← Dataset legível — treino
│       ├── dataset_val.csv          ← Dataset legível — validação
│       └── dataset_test.csv         ← Dataset legível — teste
├── models/
│   ├── word_tfidf.joblib            ← Vetorizador TF-IDF word
│   ├── char_tfidf.joblib            ← Vetorizador TF-IDF char
│   ├── manual_scaler.joblib         ← Scaler das features manuais
│   ├── feature_scaler.joblib        ← Scaler global da matriz X
│   └── random_forest.joblib         ← Modelo treinado
├── reports/
│   ├── metrics_test.json            ← Métricas completas do teste
│   └── false_positives.csv          ← Análise de falsos positivos
├── 01_collect.py
├── 02_curate.py
├── 03_features.py
├── 04_train_validate.py
├── 05_fp_analysis.py
├── 06_export_dataset.py
├── run_pipeline.sh
├── requirements.txt
└── DATASET_DOCUMENTATION.md        ← Este arquivo
```