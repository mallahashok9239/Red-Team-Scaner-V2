#!/bin/bash
# RedTeam Scanner v2 - by AnonSec777 
set -o errexit
set -o pipefail
set -o nounset

# ---------------------------
# Configuración (ajusta aquí)
# ---------------------------
target="${1:-}"
TIMEOUT_SECONDS=180
OUT_BASE="outputs"

# Rutas por defecto (modifica si tus binarios están en otra parte)
SUBFINDER="${SUBFINDER:-/home/kali/go/bin/subfinder}"
ASSETFINDER="${ASSETFINDER:-/home/kali/go/bin/assetfinder}"
DNSX="${DNSX:-/home/kali/go/bin/dnsx}"
NAABU="${NAABU:-/home/kali/go/bin/naabu}"
HTTPX="${HTTPX:-/home/kali/go/bin/httpx}"
GAU="${GAU:-/home/kali/go/bin/gau}"
WAYBACKURLS="${WAYBACKURLS:-/home/kali/go/bin/waybackurls}"
DALFOX="${DALFOX:-/home/kali/go/bin/dalfox}"
NUCLEI="${NUCLEI:-/home/kali/go/bin/nuclei}"
FFUF="${FFUF:-/home/kali/go/bin/ffuf}"

# --- Cambios para Ollama proporcionados por ti ---
OLLAMA_BIN="${OLLAMA_BIN:-/usr/local/bin/ollama}"
OLLAMA_MODEL="${OLLAMA_MODEL:-}"

# ---------------------------
# Comprobación básica del objetivo
# ---------------------------
if [ -z "$target" ]; then
    echo "Uso: $0 <url o dominio>"
    exit 1
fi

start_time="$(date '+%Y-%m-%d %H:%M:%S')"
domain="$(echo "$target" | sed -E 's#https?://##' | sed 's#/.*##')"
outdir="${OUT_BASE}/${domain//\//_}"
mkdir -p "$outdir"
aggregate="${outdir}/${domain}_aggregate.txt"

# ---------------------------
# Banner
# ---------------------------
banner(){
    clear
    echo -e "\e[91m
╻ ╻┏━┓┏━╸╻┏ ╻┏┓╻┏━╸   ╺┳╸┏━╸┏━┓┏┳┓   ┏━┓┏━╸╺┳┓   ╺┳╸┏━╸┏━┓┏┳┓   ╻ ╻┏━┓
┣━┫┣━┫┃  ┣┻┓┃┃┗┫┃╺┓    ┃ ┣╸ ┣━┫┃┃┃   ┣┳┛┣╸  ┃┃    ┃ ┣╸ ┣━┫┃┃┃   ┃┏┛┏━┛
╹ ╹╹ ╹┗━╸╹ ╹╹╹ ╹┗━┛    ╹ ┗━╸╹ ╹╹ ╹   ╹┗╸┗━╸╺┻┛    ╹ ┗━╸╹ ╹╹ ╹   ┗┛ ┗━╸
                💀 RedTeam Scanner v2 - by AnonSec777 💀
    \e[0m"
    echo "Fecha de inicio: $start_time"
    echo "Escaneando: $target"
    echo "Resultados: $outdir"
    echo "──────────────────────────────────────────────"
}
banner

# ---------------------------
# Timeout seguro (soporta --foreground si existe)
# ---------------------------
_timeout_cmd() {
    # $1 = seconds, $2.. = command...
    if timeout --help 2>&1 | grep -q -- '--foreground'; then
        timeout --foreground "$@"
    else
        timeout "$@"
    fi
}

# ---------------------------
# run_tool mejorado
# ---------------------------
run_tool(){
    local name="$1"
    local cmd="$2"
    local outfile="$3"

    echo "[INFO] Ejecutando $name..."
    echo "[CMD][$name] $cmd" >> "$aggregate"

    if _timeout_cmd "${TIMEOUT_SECONDS}" bash -c "$cmd" > "$outfile" 2>&1; then
        echo "[OK] $name completado" | tee -a "$aggregate"
    else
        rc=$?
        if [ "$rc" -eq 124 ] || [ "$rc" -eq 137 ]; then
            echo "[WARN] $name terminado por timeout (codigo $rc)" | tee -a "$aggregate"
        elif [ "$rc" -eq 139 ]; then
            echo "[ERROR] $name se estrelló (segfault, exit 139). Ejecuta la herramienta en modo interactivo para investigar." | tee -a "$aggregate"
        else
            echo "[WARN] $name falló o no produjo salida (codigo $rc)" | tee -a "$aggregate"
        fi
    fi
}

# ---------------------------
# Helper: check bin
# ---------------------------
check_bin(){
    local binpath="$1"
    local varname="$2"
    if [ -z "$binpath" ]; then
        echo "[WARN] Ruta para $varname vacía" | tee -a "$aggregate"
        return 1
    fi
    if [ -x "$binpath" ]; then
        return 0
    fi
    if command -v "$(basename "$binpath")" >/dev/null 2>&1; then
        return 0
    fi
    echo "[WARN] $varname no encontrado en $binpath ni en PATH. Saltando $varname." | tee -a "$aggregate"
    return 1
}

# ---------------------------
# Ejecutar herramientas (comprobamos si existen)
# ---------------------------

if check_bin "$SUBFINDER" "SUBFINDER"; then
    run_tool "subfinder" "$SUBFINDER -d \"$domain\" -silent" "$outdir/subfinder.txt"
fi

if check_bin "$ASSETFINDER" "ASSETFINDER"; then
    run_tool "assetfinder" "$ASSETFINDER --subs-only \"$domain\"" "$outdir/assetfinder.txt"
fi

if command -v curl >/dev/null 2>&1 && command -v jq >/dev/null 2>&1; then
    run_tool "crt.sh" "curl -s \"https://crt.sh/?q=%25.$domain&output=json\" | jq -r '.[].name_value' | sort -u" "$outdir/crt.txt"
else
    echo "[WARN] curl o jq no disponibles: saltando crt.sh" | tee -a "$aggregate"
fi

if check_bin "$DNSX" "DNSX"; then
    run_tool "dnsx" "printf '%s\n' \"$domain\" | $DNSX -silent -a -aaaa -cname -resp" "$outdir/dnsx.txt"
fi

if check_bin "$NAABU" "NAABU"; then
    run_tool "naabu" "$NAABU -host \"$domain\" -rate 100 -retries 1 -silent" "$outdir/naabu.txt"
fi

if check_bin "$HTTPX" "HTTPX"; then
    run_tool "httpx" "printf '%s\n' \"https://$domain\" | $HTTPX -silent -title -status-code -content-length -timeout 10" "$outdir/httpx.txt"
fi

if check_bin "$GAU" "GAU"; then
    run_tool "gau" "$GAU \"$domain\" --subs" "$outdir/gau.txt"
fi

if check_bin "$WAYBACKURLS" "WAYBACKURLS"; then
    run_tool "waybackurls" "printf '%s\n' \"$domain\" | $WAYBACKURLS" "$outdir/waybackurls.txt"
fi

if check_bin "$DALFOX" "DALFOX"; then
    # Ajuste: usar modo 'url' que es la forma recomendada por la documentación de dalfox
    run_tool "dalfox" "$DALFOX url \"https://$domain\" -S -o \"$outdir/dalfox.txt\"" "$outdir/dalfox.log"
else
    echo "[WARN] dalfox no disponible: saltando dalfox" | tee -a "$aggregate"
fi

if check_bin "$NUCLEI" "NUCLEI"; then
    TEMPLATES_DIR="${TEMPLATES_DIR:-$HOME/.local/nuclei-templates}"
    if [ ! -d "$TEMPLATES_DIR" ]; then
        echo "[WARN] nuclei templates no encontrado en $TEMPLATES_DIR. Ejecuta nuclei -update-templates o ajusta TEMPLATES_DIR." | tee -a "$aggregate"
    fi
    run_tool "nuclei" "$NUCLEI -u \"https://$domain\" -t \"$TEMPLATES_DIR\" -silent -o \"$outdir/nuclei.txt\"" "$outdir/nuclei.log"
fi

if check_bin "$FFUF" "FFUF"; then
    WORDLIST="${WORDLIST:-/usr/share/wordlists/dirb/common.txt}"
    run_tool "ffuf" "$FFUF -u https://$domain/FUZZ -w \"$WORDLIST\" -t 40 -fc 404 -of csv -o \"$outdir/ffuf.txt\"" "$outdir/ffuf.log"
fi

# ---------------------------
# Análisis IA (Ollama preferido)
# ---------------------------
ai_analysis(){
    local in_nuclei="$outdir/nuclei.txt"
    if [ ! -f "$in_nuclei" ]; then
        echo "[WARN] No se encontró $in_nuclei para análisis IA." | tee -a "$aggregate"
        return
    fi

    echo "[INFO] Iniciando análisis IA de resultados nuclei..." | tee -a "$aggregate"

    prompt_file="$(mktemp)"

    # Añadimos un 'system prompt' fijo orientado a auditoría y búsqueda de vulnerabilidades
    cat > "$prompt_file" <<'EOF'
Eres un auditor de seguridad (Red Team / Bug Bounty) experto en encontrar vulnerabilidades web y API.
Analiza el contenido que viene a continuación y:
  1) Resume las pruebas / hallazgos (tipo de vulnerabilidad, riesgo).
  2) Prioriza por impacto (Alta/Media/Baja) y justifica.
  3) Da pasos concretos de reproducción (requests, parámetros, payloads) cuando sea posible.
  4) Propón mitigaciones concretas y recomendaciones técnicas.

RESPONDE EN ESPAÑOL y mantén el formato: Resumen:, Impacto:, Reproducción:, Recomendaciones:.
---
EOF

    # Añadimos los primeros 4000 lineas del resultado nuclei (o todo si es menor)
    sed -n '1,4000p' "$in_nuclei" >> "$prompt_file" || true

    # Si existe Ollama en la ruta indicada, lo usamos
    if [ -x "$OLLAMA_BIN" ] || command -v "$(basename "$OLLAMA_BIN")" >/dev/null 2>&1; then
        # Si no se especificó modelo, intentamos tomar el primero disponible con 'ollama ls'
        if [ -z "${OLLAMA_MODEL:-}" ]; then
            candidate="$("$OLLAMA_BIN" ls 2>/dev/null | awk 'NR>1{print $1; exit}')" || true
            if [ -z "$candidate" ]; then
                candidate="$("$OLLAMA_BIN" ls --quiet 2>/dev/null | awk 'NR==1{print $1}')" || true
            fi
            OLLAMA_MODEL="${OLLAMA_MODEL:-$candidate}"
        fi

        if [ -n "${OLLAMA_MODEL:-}" ]; then
            echo "[INFO] Usando Ollama ($OLLAMA_BIN) con modelo: $OLLAMA_MODEL" | tee -a "$aggregate"
            # IMPORTANTE: usar pipe (cat file | ollama run ...) evita modo interactivo en la mayoría de versiones CLI
            if cat "$prompt_file" | "$OLLAMA_BIN" run "$OLLAMA_MODEL" --no-spinner --no-color > "$outdir/ia_nuclei_analysis.txt" 2>> "$aggregate"; then
                echo "[OK] Análisis IA (ollama) completado. Salida: ia_nuclei_analysis.txt" | tee -a "$aggregate"
            else
                echo "[WARN] Ollama falló al generar análisis. Revisar logs en $aggregate." | tee -a "$aggregate"
            fi
            rm -f "$prompt_file"
            return
        else
            echo "[WARN] Ollama instalado pero no se detectó ningún modelo. Ejecuta 'ollama ls' para ver modelos." | tee -a "$aggregate"
        fi
    else
        echo "[INFO] Ollama no encontrado en $OLLAMA_BIN; se intentará python/transformers si está disponible." | tee -a "$aggregate"
    fi

    # Si no hay ollama o no hay modelo, intentamos con python+transformers (si están instalados)
    if python3 -c "import sys, pkgutil; exit(0 if pkgutil.find_loader('transformers') and pkgutil.find_loader('torch') else 1)" >/dev/null 2>&1; then
        echo "[INFO] Ejecutando análisis con transformers local (python)." | tee -a "$aggregate"
        python3 <<PYEOF
import sys
from transformers import AutoModelForCausalLM, AutoTokenizer
model_path = "/ruta/a/tu/modelo"  # Cambia si usas HF local
try:
    tokenizer = AutoTokenizer.from_pretrained(model_path)
    model = AutoModelForCausalLM.from_pretrained(model_path)
except Exception as e:
    print(f"[ERROR] No se pudo cargar modelo: {e}")
    sys.exit(1)
with open(r"$in_nuclei", "r", encoding="utf-8") as f:
    content = f.read()
prompt = "Analiza las posibles vulnerabilidades y da recomendaciones:\n\n" + content
inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=1024)
outs = model.generate(**inputs, max_length=512)
result = tokenizer.decode(outs[0], skip_special_tokens=True)
with open(r"$outdir/ia_nuclei_analysis.txt", "w", encoding="utf-8") as out:
    out.write(result)
print("[OK] Análisis IA completado (transformers).")
PYEOF
        rm -f "$prompt_file"
        return
    fi

    echo "[WARN] Ni ollama ni transformers disponibles. Saltando análisis IA." | tee -a "$aggregate"
    rm -f "$prompt_file"
}

ai_analysis

# ---------------------------
# Finalización
# ---------------------------
end_time="$(date '+%Y-%m-%d %H:%M:%S')"
echo "──────────────────────────────────────────────" | tee -a "$aggregate"
echo "🕒 Fecha de finalización: $end_time" | tee -a "$aggregate"
echo "📁 Resultados almacenados en: $outdir" | tee -a "$aggregate"
echo "💀 Escaneo completado por: AnonSec777 💀" | tee -a "$aggregate"
