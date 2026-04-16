#!/usr/bin/env bash
# Executa o pipeline completo em sequência.
# Para em qualquer estágio que retornar exit code != 0.

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

PYTHON="${PYTHON:-python}"

run_stage() {
    local stage_num="$1"
    local script="$2"
    echo ""
    echo "========================================================"
    echo "  ESTÁGIO ${stage_num} — ${script}"
    echo "========================================================"
    if "$PYTHON" "$script"; then
        echo ""
        echo "  [OK] ${script} concluído com sucesso."
    else
        echo ""
        echo "  [ERRO] ${script} falhou (exit code $?)."
        echo "  Pipeline interrompido no estágio ${stage_num}."
        exit 1
    fi
}

echo "========================================================"
echo "  PIPELINE DE DATASET — WAF com IA"
echo "  Início: $(date)"
echo "========================================================"

run_stage 1 "01_collect.py"
run_stage 2 "02_curate.py"
run_stage 3 "03_features.py"
run_stage 4 "04_train_validate.py"
run_stage 5 "05_fp_analysis.py"

echo ""
echo "========================================================"
echo "  PIPELINE CONCLUÍDO COM SUCESSO"
echo "  Fim: $(date)"
echo "========================================================"
