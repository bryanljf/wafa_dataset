"""
Integração do modelo Random Forest com a biblioteca wafahell.

Uso:
    from wafahell_integration import WAFAHellMLDetector

    detector = WAFAHellMLDetector(
        model_path="models/random_forest.joblib",
        vectorizers_path="models/",
        threshold=0.5
    )

    result = detector.predict(payload="' OR '1'='1")
    # result = {"threat": "sqli", "confidence": 0.95, "allow": False}
"""

import warnings
from pathlib import Path
from typing import Dict, Tuple

import joblib
import numpy as np
import scipy.sparse as sp

warnings.filterwarnings("ignore")


class WAFAHellMLDetector:
    """
    Detector de ataques web baseado em Machine Learning para wafahell.

    Integra o modelo Random Forest treinado com suporte a:
    - Detecção de SQLi e XSS
    - Features de TF-IDF + features manuais
    - Confiança/probabilidade de predição
    - Threshold customizável
    """

    LABELS = {0: "sqli", 1: "xss", 2: "benign"}
    REVERSE_LABELS = {"sqli": 0, "xss": 1, "benign": 2}

    def __init__(
        self,
        model_path: str,
        vectorizers_path: str = None,
        threshold: float = 0.5,
        verbose: bool = False,
    ):
        """
        Inicializa o detector ML.

        Args:
            model_path: Caminho para random_forest.joblib
            vectorizers_path: Caminho da pasta contendo os vetorizadores
                             (word_tfidf.joblib, char_tfidf.joblib, feature_scaler.joblib)
            threshold: Confiança mínima para considerar como ameaça (0-1)
            verbose: Imprimir logs de carregamento
        """
        self.threshold = threshold
        self.verbose = verbose

        if vectorizers_path is None:
            vectorizers_path = str(Path(model_path).parent)

        vectorizers_path = Path(vectorizers_path)

        # Carregar modelo
        self.model = joblib.load(model_path)
        if verbose:
            print(f"[✓] Modelo carregado: {model_path}")

        # Carregar vetorizadores
        self.word_tfidf = joblib.load(vectorizers_path / "word_tfidf.joblib")
        self.char_tfidf = joblib.load(vectorizers_path / "char_tfidf.joblib")
        self.feature_scaler = joblib.load(vectorizers_path / "feature_scaler.joblib")

        if verbose:
            print(f"[✓] Vetorizadores carregados de: {vectorizers_path}")

    def extract_manual_features(self, payload: str) -> np.ndarray:
        """Extrai as 15 features manuais estruturais."""
        import re

        p = payload if isinstance(payload, str) else ""
        pl = p.lower()

        SQL_KW = [
            "select", "union", "insert", "drop", "update", "delete", "where",
            "having", "exec", "xp_", "information_schema", "sleep", "benchmark",
            "cast", "convert",
        ]
        XSS_KW = [
            "script", "onerror", "onload", "alert", "javascript", "iframe",
            "document.", "cookie", "eval(", "src=", "href=", "onclick",
        ]

        pat_1eq1 = re.compile(r"\d+=\d+")
        pat_script = re.compile(r"<\s*script", re.IGNORECASE)
        pat_handler = re.compile(r"on\w+\s*=", re.IGNORECASE)

        feats = np.array([
            len(p),
            p.count("'"),
            p.count('"'),
            p.count("<"),
            p.count(">"),
            p.count(";"),
            p.count("("),
            p.count("%"),
            p.count("--"),
            p.count("/*"),
            sum(1 for kw in SQL_KW if kw in pl),
            sum(1 for kw in XSS_KW if kw in pl),
            int(bool(pat_1eq1.search(p))),
            int(bool(pat_script.search(p))),
            int(bool(pat_handler.search(p))),
        ], dtype=np.float32)

        return feats

    def vectorize_payload(self, payload: str) -> sp.csr_matrix:
        """Vetoriza o payload em 20.015 features."""
        # TF-IDF word
        X_word = self.word_tfidf.transform([payload])

        # TF-IDF char
        X_char = self.char_tfidf.transform([payload])

        # Features manuais
        X_manual_dense = self.extract_manual_features(payload).reshape(1, -1)
        X_manual_sparse = sp.csr_matrix(X_manual_dense)

        # Concatenar
        X = sp.hstack([X_word, X_char, X_manual_sparse], format="csr")

        # Normalizar
        X = self.feature_scaler.transform(X)

        return X

    def predict(self, payload: str) -> Dict[str, any]:
        """
        Prediz a classe e confiança de um payload.

        Args:
            payload: String da requisição HTTP

        Returns:
            {
                "threat": "sqli" | "xss" | "benign",
                "confidence": float (0-1),
                "allow": bool,
                "probabilities": {
                    "sqli": float,
                    "xss": float,
                    "benign": float,
                },
                "ml_decision": bool,  # True se confiante na ameaça
            }
        """
        # Vetorizar
        X = self.vectorize_payload(payload)

        # Prever classe e probabilidades
        pred_class = self.model.predict(X)[0]
        probabilities = self.model.predict_proba(X)[0]

        threat_label = self.LABELS[pred_class]
        confidence = float(probabilities[pred_class])

        # Decisão: bloquear se não é benign E confiança > threshold
        is_threat = pred_class != 2  # 2 = benign
        ml_decision = is_threat and confidence > self.threshold

        return {
            "threat": threat_label,
            "confidence": confidence,
            "allow": not ml_decision,
            "probabilities": {
                "sqli": float(probabilities[0]),
                "xss": float(probabilities[1]),
                "benign": float(probabilities[2]),
            },
            "ml_decision": ml_decision,
        }

    def batch_predict(self, payloads: list) -> list:
        """Prediz múltiplos payloads."""
        return [self.predict(p) for p in payloads]


# Exemplo de integração com wafahell (assumindo interface similar a WAF)
class WAFAHellMLMiddleware:
    """
    Middleware para integrar o detector ML com wafahell.

    Uso em FastAPI:
        app = FastAPI()
        ml_waf = WAFAHellMLMiddleware(
            model_path="models/random_forest.joblib",
            vectorizers_path="models/"
        )

        @app.middleware("http")
        async def waf_middleware(request, call_next):
            return await ml_waf.process_request(request, call_next)
    """

    def __init__(self, model_path: str, vectorizers_path: str = None):
        self.detector = WAFAHellMLDetector(
            model_path=model_path,
            vectorizers_path=vectorizers_path,
            verbose=True,
        )

    async def process_request(self, request, call_next):
        """
        Processa requisição e bloqueia se detectar ataque.
        """
        from fastapi import HTTPException

        # Extrair payload (query string + body)
        try:
            # Query params
            query_string = str(request.url.query)

            # Body (se POST/PUT/PATCH)
            body = ""
            if request.method in ["POST", "PUT", "PATCH"]:
                try:
                    body = await request.body()
                    body = body.decode("utf-8", errors="replace")
                except Exception:
                    body = ""

            payload = (query_string + " " + body).strip()

            # Detectar
            result = self.detector.predict(payload)

            # Log
            print(f"[WAF-ML] {request.method} {request.url.path}")
            print(f"         Threat: {result['threat']}, "
                  f"Confidence: {result['confidence']:.3f}, "
                  f"Allow: {result['allow']}")

            # Bloquear se ameaça detectada
            if not result["allow"]:
                raise HTTPException(
                    status_code=403,
                    detail=f"Ataque detectado: {result['threat']} "
                           f"(confiança: {result['confidence']:.1%})",
                )

        except HTTPException:
            raise
        except Exception as e:
            # Em caso de erro, deixar passar (fail-open)
            print(f"[WAF-ML] Erro ao processar: {e}")

        # Continuar processamento normal
        response = await call_next(request)
        return response


if __name__ == "__main__":
    # Exemplo de uso standalone
    detector = WAFAHellMLDetector(
        model_path="models/random_forest.joblib",
        vectorizers_path="models/",
        threshold=0.5,
        verbose=True,
    )

    # Testar com payloads de exemplo
    test_payloads = [
        "' OR '1'='1",  # SQLi
        "<script>alert(1)</script>",  # XSS
        "SELECT * FROM users",  # SQLi
        "usuario=joao&senha=123",  # Benign
        "q=como usar SELECT em SQL",  # Benign
    ]

    print("\n" + "=" * 60)
    print("TESTE DO DETECTOR ML")
    print("=" * 60)

    for payload in test_payloads:
        result = detector.predict(payload)
        status = "🚫 BLOQUEADO" if not result["allow"] else "✅ PERMITIDO"
        print(f"\n{status}")
        print(f"  Payload: {payload[:50]}...")
        print(f"  Threat:  {result['threat']}")
        print(f"  Confidence: {result['confidence']:.1%}")
        print(f"  Probs:   sqli={result['probabilities']['sqli']:.3f}, "
              f"xss={result['probabilities']['xss']:.3f}, "
              f"benign={result['probabilities']['benign']:.3f}")