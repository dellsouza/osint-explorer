"""
Attack Surface Mapper + Auditor Passivo
=======================================
Mapeia a superfície de ataque de um domínio usando fontes públicas (Certificate
Transparency, DNS) e faz uma auditoria leve de configuração (headers, cookies, TLS,
CORS, e-mail, subdomain takeover).

USE SOMENTE em domínios seus ou com autorização escrita do responsável.
Não executa exploração, força bruta nem varredura de portas.
"""
import hmac
import html as htmllib
import io
import ipaddress
import re
import socket
import ssl
import uuid  # noqa: F401  (reservado)
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urljoin, urlparse

import dns.resolver
import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="Attack Surface Mapper", page_icon="🛰️", layout="wide")

UA = "AttackSurfaceMapper/1.0 (auditoria autorizada)"
HTTP_TIMEOUT = 8
MAX_BODY = 200_000
SEV_ORDER = {"Crítica": 0, "Alta": 1, "Média": 2, "Baixa": 3, "Info": 4}
SEV_EMOJI = {"Crítica": "🔴", "Alta": "🟠", "Média": "🟡", "Baixa": "🔵", "Info": "⚪"}
SEV_WEIGHT = {"Crítica": 25, "Alta": 10, "Média": 4, "Baixa": 1, "Info": 0}
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


# ============================================================================
# Utilidades
# ============================================================================
def secret(key):
    try:
        return st.secrets.get(key)
    except Exception:
        return None


def add(findings, sev, host, cat, title, evidence="", fix=""):
    findings.append({
        "Severidade": sev, "Host": host, "Categoria": cat,
        "Achado": title, "Evidência": evidence, "Recomendação": fix,
    })


def clean_domain(value):
    v = (value or "").strip().lower()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/")[0].split(":")[0].strip(".")
    return v.removeprefix("www.")


def is_public_ip(ip):
    try:
        return ipaddress.ip_address(ip).is_global
    except ValueError:
        return False


def host_is_public(host):
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        return False
    return bool(infos) and all(is_public_ip(i[4][0]) for i in infos)


def txt_clean(t):
    return re.sub(r'"\s+"', "", t).strip('"')


# ============================================================================
# DNS
# ============================================================================
def dns_query(name, rtype):
    r = dns.resolver.Resolver()
    r.nameservers = ["1.1.1.1", "8.8.8.8"]
    r.timeout, r.lifetime = 3, 5
    try:
        ans = r.resolve(name, rtype)
        return [a.to_text() for a in ans], None
    except dns.resolver.NXDOMAIN:
        return [], "NXDOMAIN"
    except dns.resolver.NoAnswer:
        return [], "NOANSWER"
    except Exception as e:  # noqa: BLE001
        return [], type(e).__name__


def resolve_host(host):
    cname, _ = dns_query(host, "CNAME")
    a, a_err = dns_query(host, "A")
    aaaa, _ = dns_query(host, "AAAA")
    return {"host": host, "cname": cname[0].rstrip(".") if cname else "",
            "a": a, "aaaa": aaaa, "a_err": a_err}


# ============================================================================
# Certificate Transparency
# ============================================================================
def _valid_sub(n, domain):
    n = n.strip().lower().lstrip("*.")
    if re.fullmatch(r"[a-z0-9.-]+", n) and (n == domain or n.endswith("." + domain)):
        return n
    return None


@st.cache_data(ttl=3600, show_spinner=False)
def ct_lookup(domain):
    """Retorna (lista_de_nomes, fonte). Levanta exceção se nada for obtido (não entra no cache)."""
    names, errors = set(), []
    for attempt in range(2):
        try:
            r = requests.get("https://crt.sh/", params={"q": f"%.{domain}", "output": "json"},
                             headers={"User-Agent": UA}, timeout=40)
            r.raise_for_status()
            for row in r.json():
                for n in row.get("name_value", "").split("\n"):
                    v = _valid_sub(n, domain)
                    if v:
                        names.add(v)
            if names:
                return sorted(names), "crt.sh"
        except Exception as e:  # noqa: BLE001
            errors.append(f"crt.sh: {type(e).__name__}")
    try:
        r = requests.get("https://api.certspotter.com/v1/issuances",
                         params={"domain": domain, "include_subdomains": "true", "expand": "dns_names"},
                         headers={"User-Agent": UA}, timeout=30)
        r.raise_for_status()
        for row in r.json():
            for n in row.get("dns_names", []):
                v = _valid_sub(n, domain)
                if v:
                    names.add(v)
        if names:
            return sorted(names), "certspotter"
    except Exception as e:  # noqa: BLE001
        errors.append(f"certspotter: {type(e).__name__}")
    raise RuntimeError("; ".join(errors) or "nenhum certificado encontrado")


# ============================================================================
# HTTP seguro (anti-SSRF: só hosts públicos, portas 80/443, redirecionamentos validados)
# ============================================================================
def safe_request(method, url, headers=None, max_redirects=4, verify=True):
    h = {"User-Agent": UA, "Accept": "*/*"}
    h.update(headers or {})
    for i in range(max_redirects + 1):
        p = urlparse(url)
        if p.scheme not in ("http", "https") or not p.hostname:
            raise ValueError("URL inválida")
        if p.port not in (None, 80, 443):
            raise ValueError("porta não permitida")
        if not host_is_public(p.hostname):
            raise ValueError("host não público")
        r = requests.request(method, url, headers=h, timeout=HTTP_TIMEOUT,
                             allow_redirects=False, verify=verify, stream=True)
        if r.is_redirect and r.headers.get("Location") and i < max_redirects:
            url = urljoin(url, r.headers["Location"])
            r.close()
            continue
        try:
            raw = r.raw.read(MAX_BODY, decode_content=True) or b""
        except Exception:  # noqa: BLE001
            raw = b""
        try:
            cookies = r.raw.headers.getlist("Set-Cookie")
        except Exception:  # noqa: BLE001
            cookies = []
        out = {"url": url, "status": r.status_code, "headers": dict(r.headers), "cookies": cookies,
               "body": raw.decode(r.encoding or "utf-8", errors="ignore")}
        r.close()
        return out
    raise ValueError("redirecionamentos excedidos")


# ============================================================================
# TLS
# ============================================================================
def tls_info(host, port=443):
    ctx = ssl.create_default_context()
    try:
        with socket.create_connection((host, port), timeout=6) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                cert = ss.getpeercert()
                exp = datetime.fromtimestamp(ssl.cert_time_to_seconds(cert["notAfter"]), timezone.utc)
                issuer = dict(x[0] for x in cert.get("issuer", ())).get("organizationName", "?")
                return {"ok": True, "dias": (exp - datetime.now(timezone.utc)).days,
                        "expira": exp.strftime("%Y-%m-%d"), "emissor": issuer, "versao": ss.version()}
    except ssl.SSLCertVerificationError as e:
        return {"ok": False, "erro": e.verify_message}
    except Exception as e:  # noqa: BLE001
        return {"ok": None, "erro": type(e).__name__}


# ============================================================================
# Fingerprint de tecnologias
# ============================================================================
BODY_SIGS = {
    "WordPress": "wp-content", "Joomla": "/media/jui/", "Drupal": "drupal-settings-json",
    "Shopify": "cdn.shopify.com", "Wix": "static.wixstatic.com", "Next.js": "/_next/",
    "Angular": "ng-version", "Elementor": "elementor", "WooCommerce": "woocommerce",
}
COOKIE_SIGS = {
    "PHPSESSID": "PHP", "JSESSIONID": "Java", "laravel_session": "Laravel",
    "connect.sid": "Node/Express", "ASP.NET_SessionId": "ASP.NET",
}
HEADER_SIGS = {
    "cf-ray": "Cloudflare", "x-vercel-id": "Vercel", "x-amz-cf-id": "CloudFront",
    "x-github-request-id": "GitHub Pages", "x-served-by": "Fastly/Varnish",
}


def fingerprint(headers, cookies, body):
    h = {k.lower(): v for k, v in headers.items()}
    tech = set()
    for k, name in HEADER_SIGS.items():
        if k in h:
            tech.add(name)
    server = h.get("server", "")
    if server:
        tech.add(server.split(" ")[0])
    if h.get("x-powered-by"):
        tech.add(h["x-powered-by"].split(" ")[0])
    low = body.lower()
    for name, sig in BODY_SIGS.items():
        if sig.lower() in low:
            tech.add(name)
    cookie_blob = " ".join(cookies)
    for sig, name in COOKIE_SIGS.items():
        if sig in cookie_blob:
            tech.add(name)
    m = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', body, re.I)
    if m:
        tech.add(m.group(1)[:40])
    return sorted(tech)


# ============================================================================
# Análises
# ============================================================================
def analyze_response(host, resp, tls_err, findings):
    h = {k.lower(): v for k, v in resp["headers"].items()}
    https = resp["url"].startswith("https://")
    if resp["status"] >= 500:
        return
    if not https:
        add(findings, "Média", host, "Transporte", "Site acessível apenas por HTTP",
            resp["url"], "Instalar certificado TLS e redirecionar HTTP para HTTPS.")
    if tls_err:
        add(findings, "Alta", host, "TLS", "Certificado TLS inválido ou não confiável",
            tls_err[:160], "Emitir/renovar certificado válido para este hostname.")

    missing = []
    if https and "strict-transport-security" not in h:
        missing.append("HSTS")
    csp = h.get("content-security-policy", "")
    if not csp:
        missing.append("CSP")
    if not (h.get("x-frame-options") or "frame-ancestors" in csp.lower()):
        missing.append("X-Frame-Options/frame-ancestors")
    if h.get("x-content-type-options", "").lower() != "nosniff":
        missing.append("X-Content-Type-Options")
    if "referrer-policy" not in h:
        missing.append("Referrer-Policy")
    if missing:
        add(findings, "Baixa", host, "Headers", "Cabeçalhos de segurança ausentes", ", ".join(missing),
            "Configurar os cabeçalhos no servidor web ou CDN.")

    server = h.get("server", "")
    if re.search(r"\d+\.\d+", server):
        add(findings, "Baixa", host, "Exposição de informação", "Versão do servidor exposta", server,
            "Ocultar versão (ServerTokens Prod / server_tokens off).")
    if h.get("x-powered-by"):
        add(findings, "Baixa", host, "Exposição de informação", "Header X-Powered-By presente",
            h["x-powered-by"], "Remover o header.")

    for c in resp["cookies"]:
        name = c.split("=", 1)[0].strip()
        attrs = [a.strip().lower() for a in c.split(";")[1:]]
        miss = []
        if https and "secure" not in attrs:
            miss.append("Secure")
        if "httponly" not in attrs:
            miss.append("HttpOnly")
        if not any(a.startswith("samesite") for a in attrs):
            miss.append("SameSite")
        if miss:
            sess = bool(re.search(r"sess|auth|token|sid|jwt|login", name, re.I))
            sev = "Média" if sess and ("Secure" in miss or "HttpOnly" in miss) else "Baixa"
            add(findings, sev, host, "Cookies", "Cookie sem flags de segurança",
                f"{name}: sem {', '.join(miss)}", "Definir Secure, HttpOnly e SameSite=Lax/Strict.")


def check_cors(base_url, host, findings):
    origin = "https://evil.example"
    try:
        r = safe_request("GET", base_url, headers={"Origin": origin}, max_redirects=2)
    except Exception:  # noqa: BLE001
        return
    h = {k.lower(): v for k, v in r["headers"].items()}
    acao = h.get("access-control-allow-origin", "")
    acac = h.get("access-control-allow-credentials", "").lower()
    if acao == origin and acac == "true":
        add(findings, "Alta", host, "CORS", "CORS reflete origem arbitrária com credenciais",
            f"ACAO={acao}; ACAC=true", "Usar lista fixa de origens confiáveis; nunca refletir o Origin.")
    elif acao == origin:
        add(findings, "Média", host, "CORS", "CORS reflete origem arbitrária", f"ACAO={acao}",
            "Usar lista fixa de origens confiáveis.")


def check_methods(base_url, host, findings):
    try:
        r = safe_request("OPTIONS", base_url, max_redirects=0)
    except Exception:  # noqa: BLE001
        return
    allow = {k.lower(): v for k, v in r["headers"].items()}.get("allow", "").upper()
    risky = [m for m in ("TRACE", "PUT", "DELETE", "CONNECT") if m in allow]
    if risky:
        add(findings, "Média", host, "Métodos HTTP", "Métodos HTTP de risco anunciados",
            f"Allow: {allow}", "Desabilitar métodos não utilizados.")


SENSITIVE = [
    ("/.git/HEAD", lambda b: b.strip().startswith("ref:"), "Crítica", "Repositório .git exposto",
     "Bloquear acesso a /.git e remover do servidor de produção."),
    ("/.env", lambda b: bool(re.search(r"^[A-Za-z_][A-Za-z0-9_]*=.+", b, re.M)) and "<html" not in b[:300].lower(),
     "Crítica", "Arquivo .env exposto", "Remover o arquivo, bloquear acesso e girar todas as credenciais."),
    ("/phpinfo.php", lambda b: "phpinfo()" in b or "PHP Version" in b, "Alta", "phpinfo() exposto",
     "Remover o arquivo."),
    ("/actuator/env", lambda b: '"propertySources"' in b, "Alta", "Spring Actuator /env exposto",
     "Restringir endpoints do Actuator."),
    ("/server-status", lambda b: "Apache Server Status" in b, "Média", "Apache server-status exposto",
     "Restringir a IPs internos."),
    ("/wp-json/wp/v2/users", lambda b: b.strip().startswith("[") and '"slug"' in b, "Média",
     "Enumeração de usuários WordPress via REST API", "Restringir o endpoint /wp-json/wp/v2/users."),
    ("/openapi.json", lambda b: '"openapi"' in b, "Baixa", "Documentação de API exposta (openapi.json)",
     "Restringir acesso se a API não for pública."),
    ("/swagger.json", lambda b: '"swagger"' in b, "Baixa", "Documentação de API exposta (swagger.json)",
     "Restringir acesso se a API não for pública."),
    ("/xmlrpc.php", lambda b: "XML-RPC server accepts POST requests only" in b, "Baixa",
     "WordPress xmlrpc.php habilitado", "Desabilitar se não for usado."),
]


def check_files(base_url, host, findings):
    origin = base_url.rstrip("/")
    for path, test, sev, title, fix in SENSITIVE:
        try:
            r = safe_request("GET", origin + path, max_redirects=2)
        except Exception:  # noqa: BLE001
            continue
        if r["status"] == 200 and test(r["body"]):
            add(findings, sev, host, "Arquivos expostos", title, f"{origin}{path}", fix)
    try:
        r = safe_request("GET", origin + "/robots.txt", max_redirects=2)
        if r["status"] == 200 and "disallow" in r["body"].lower():
            paths = re.findall(r"(?im)^disallow:\s*(\S+)", r["body"])
            hot = [p for p in paths if re.search(r"admin|backup|private|painel|config|internal|staging|test", p, re.I)]
            if hot:
                add(findings, "Info", host, "Descoberta", "robots.txt revela caminhos sensíveis",
                    ", ".join(hot[:8]), "Não depender de robots.txt para proteger áreas restritas.")
    except Exception:  # noqa: BLE001
        pass


# ----------------------------------------------------------------------------
# Subdomain takeover
# ----------------------------------------------------------------------------
TAKEOVER = [
    ("github.io", "GitHub Pages", "There isn't a GitHub Pages site here"),
    ("herokuapp.com", "Heroku", "No such app"),
    ("herokudns.com", "Heroku", "No such app"),
    ("s3.amazonaws.com", "AWS S3", "NoSuchBucket"),
    ("s3-website", "AWS S3 (website)", "NoSuchBucket"),
    ("azurewebsites.net", "Azure App Service", None),
    ("cloudapp.net", "Azure Cloud Service", None),
    ("cloudapp.azure.com", "Azure VM", None),
    ("trafficmanager.net", "Azure Traffic Manager", None),
    ("blob.core.windows.net", "Azure Blob", "BlobNotFound"),
    ("myshopify.com", "Shopify", "Sorry, this shop is currently unavailable"),
    ("ghost.io", "Ghost", "The thing you were looking for is no longer here"),
    ("surge.sh", "Surge", "project not found"),
    ("bitbucket.io", "Bitbucket", "Repository not found"),
    ("zendesk.com", "Zendesk", "Help Center Closed"),
    ("pantheonsite.io", "Pantheon", "404 error unknown site"),
    ("readme.io", "Readme", "Project doesn't exist"),
    ("wordpress.com", "WordPress.com", "Do you want to register"),
    ("helpscoutdocs.com", "HelpScout", "No settings were found for this company"),
]


def match_service(cname):
    c = cname.lower()
    for key, service, fp in TAKEOVER:
        if key in c:
            return service, fp
    return None, None


def check_takeover(host, info, body, findings):
    cname = info.get("cname", "")
    if not cname:
        return
    service, fp = match_service(cname)
    dangling = not info.get("a") and info.get("a_err") == "NXDOMAIN"
    if dangling:
        sev = "Alta" if service else "Média"
        add(findings, sev, host, "Subdomain takeover", "CNAME pendente: destino não existe",
            f"{host} → {cname}" + (f" ({service})" if service else ""),
            "Remover o registro DNS ou recriar o recurso no provedor.")
    elif service and fp and fp.lower() in (body or "").lower():
        add(findings, "Alta", host, "Subdomain takeover", f"Possível takeover em {service}",
            f"{host} → {cname}; a página exibe a mensagem de recurso inexistente",
            "Confirmar manualmente se o recurso pode ser reivindicado; remover o CNAME se não for usado.")


# ----------------------------------------------------------------------------
# Probe por host
# ----------------------------------------------------------------------------
def probe_host(host, info, do_tests, do_files):
    findings = []
    row = {"Host": host, "Status": "sem resposta", "URL final": "", "Título": "", "Servidor": "",
           "Tecnologias": "", "TLS": "", "IPs": ", ".join((info["a"] + info["aaaa"])[:3]),
           "CNAME": info["cname"]}
    resp, tls_err, last_err = None, "", ""
    attempts = [("https", True), ("https", False), ("http", True)]
    for scheme, verify in attempts:
        if scheme == "https" and not verify and not tls_err:
            continue
        try:
            resp = safe_request("GET", f"{scheme}://{host}/", verify=verify)
            break
        except requests.exceptions.SSLError as e:
            tls_err = str(e)[:160]
        except Exception as e:  # noqa: BLE001
            last_err = f"{type(e).__name__}: {str(e)[:80]}"
    if not resp:
        row["Status"] = last_err or "sem resposta"
        return row, findings, ""

    body = resp["body"]
    m = re.search(r"<title[^>]*>(.*?)</title>", body, re.I | re.S)
    row["Status"] = resp["status"]
    row["URL final"] = resp["url"]
    row["Título"] = htmllib.unescape(m.group(1)).strip()[:90] if m else ""
    row["Servidor"] = {k.lower(): v for k, v in resp["headers"].items()}.get("server", "")
    row["Tecnologias"] = ", ".join(fingerprint(resp["headers"], resp["cookies"], body))

    if resp["url"].startswith("https://") or tls_err:
        t = tls_info(host)
        if t.get("ok"):
            row["TLS"] = f"{t['dias']} dias ({t['emissor']})"
            if t["dias"] < 0:
                add(findings, "Alta", host, "TLS", "Certificado expirado", t["expira"], "Renovar o certificado.")
            elif t["dias"] <= 14:
                add(findings, "Média", host, "TLS", "Certificado expira em menos de 15 dias",
                    f"{t['dias']} dias ({t['expira']})", "Renovar e automatizar a renovação.")
            elif t["dias"] <= 30:
                add(findings, "Baixa", host, "TLS", "Certificado expira em menos de 30 dias",
                    f"{t['dias']} dias ({t['expira']})", "Programar a renovação.")
        elif t.get("ok") is False:
            row["TLS"] = f"inválido: {t.get('erro', '')[:60]}"
            tls_err = tls_err or t.get("erro", "")

    analyze_response(host, resp, tls_err, findings)
    check_takeover(host, info, body, findings)
    base = resp["url"].split("/", 3)
    base_url = "/".join(base[:3])
    if do_tests and resp["status"] < 500:
        check_cors(base_url + "/", host, findings)
        check_methods(base_url + "/", host, findings)
    if do_files and resp["status"] < 500:
        check_files(base_url, host, findings)
    return row, findings, body


# ----------------------------------------------------------------------------
# E-mail (SPF / DKIM / DMARC / CAA)
# ----------------------------------------------------------------------------
def analyze_spf(domain, txts, has_mx, findings, rows):
    spf = [txt_clean(t) for t in txts if txt_clean(t).lower().startswith("v=spf1")]
    if not spf:
        sev = "Alta" if has_mx else "Baixa"
        add(findings, sev, domain, "E-mail", "SPF ausente", "",
            "Publicar registro SPF (ex.: v=spf1 include:_spf.seuprovedor.com -all).")
        rows.append({"Controle": "SPF", "Status": "ausente", "Detalhe": ""})
        return
    if len(spf) > 1:
        add(findings, "Média", domain, "E-mail", "Múltiplos registros SPF (inválido)", " | ".join(spf),
            "Manter um único registro SPF.")
    rec = spf[0]
    tokens = rec.split()
    last = tokens[-1].lower()
    status = "ok"
    if last == "+all":
        add(findings, "Alta", domain, "E-mail", "SPF permite qualquer remetente (+all)", rec, "Usar -all ou ~all.")
        status = "inseguro"
    elif last == "?all":
        add(findings, "Média", domain, "E-mail", "SPF neutro (?all)", rec, "Usar -all ou ~all.")
        status = "fraco"
    elif last == "~all":
        add(findings, "Info", domain, "E-mail", "SPF em softfail (~all)", rec,
            "Considerar -all após validar todas as fontes de envio.")
        status = "ok (softfail)"
    elif last != "-all" and not any(t.lower().startswith("redirect=") for t in tokens):
        add(findings, "Baixa", domain, "E-mail", "SPF sem política final (all)", rec, "Terminar com -all ou ~all.")
        status = "incompleto"
    lookups = sum(1 for t in tokens if re.match(r"(?i)^[+\-~?]?(include:|a(:|$)|mx(:|$)|ptr|exists:|redirect=)", t))
    if lookups > 10:
        add(findings, "Média", domain, "E-mail", "SPF excede 10 consultas DNS (PermError)", f"{lookups} mecanismos",
            "Reduzir includes ou usar flattening.")
    rows.append({"Controle": "SPF", "Status": status, "Detalhe": rec[:140]})


def analyze_dmarc(domain, txts, has_mx, findings, rows):
    dm = [txt_clean(t) for t in txts if txt_clean(t).lower().startswith("v=dmarc1")]
    if not dm:
        sev = "Alta" if has_mx else "Baixa"
        add(findings, sev, domain, "E-mail", "DMARC ausente", "",
            "Publicar _dmarc com p=none (monitorar) e evoluir para quarantine/reject.")
        rows.append({"Controle": "DMARC", "Status": "ausente", "Detalhe": ""})
        return
    rec = dm[0]
    tags = {}
    for part in rec.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            tags[k.strip().lower()] = v.strip()
    p = tags.get("p", "").lower()
    status = f"p={p}"
    if p == "none":
        add(findings, "Média", domain, "E-mail", "DMARC apenas em monitoramento (p=none)", rec,
            "Evoluir para p=quarantine e depois p=reject.")
    elif p not in ("quarantine", "reject"):
        add(findings, "Média", domain, "E-mail", "DMARC com política inválida", rec, "Corrigir a tag p=.")
    if "rua" not in tags:
        add(findings, "Baixa", domain, "E-mail", "DMARC sem endereço de relatórios (rua)", rec,
            "Adicionar rua=mailto:... para receber relatórios.")
    try:
        if int(tags.get("pct", "100")) < 100:
            add(findings, "Baixa", domain, "E-mail", "DMARC aplicado a menos de 100% (pct)", rec, "Elevar pct para 100.")
    except ValueError:
        pass
    rows.append({"Controle": "DMARC", "Status": status, "Detalhe": rec[:140]})


DKIM_SELECTORS = ["default", "google", "selector1", "selector2", "k1", "k2", "mail", "dkim", "s1", "s2", "smtp"]


def email_audit(domain, findings):
    rows = []
    mx, _ = dns_query(domain, "MX")
    has_mx = bool(mx) and mx != ["0 ."]
    rows.append({"Controle": "MX", "Status": "ok" if has_mx else "ausente", "Detalhe": ", ".join(mx[:4])})
    txt, _ = dns_query(domain, "TXT")
    analyze_spf(domain, txt, has_mx, findings, rows)
    dmarc, _ = dns_query(f"_dmarc.{domain}", "TXT")
    analyze_dmarc(domain, dmarc, has_mx, findings, rows)
    found = []
    for sel in DKIM_SELECTORS:
        r, _ = dns_query(f"{sel}._domainkey.{domain}", "TXT")
        if any("p=" in txt_clean(x) or "v=DKIM1" in txt_clean(x) for x in r):
            found.append(sel)
    rows.append({"Controle": "DKIM", "Status": "encontrado" if found else "não identificado",
                 "Detalhe": ", ".join(found) or "Nenhum seletor comum; pode usar outro."})
    if has_mx and not found:
        add(findings, "Info", domain, "E-mail", "DKIM não identificado nos seletores comuns",
            ", ".join(DKIM_SELECTORS), "Verificar manualmente o seletor usado pelo provedor de e-mail.")
    caa, _ = dns_query(domain, "CAA")
    rows.append({"Controle": "CAA", "Status": "ok" if caa else "ausente", "Detalhe": ", ".join(caa[:3])})
    if not caa:
        add(findings, "Info", domain, "DNS", "Sem registro CAA", "",
            "Publicar CAA para restringir quais CAs podem emitir certificados.")
    return rows


# ============================================================================
# Pontuação, grafo e relatório
# ============================================================================
def grade(findings):
    total = sum(SEV_WEIGHT[f["Severidade"]] for f in findings)
    score = max(0, 100 - total)
    letter = "A" if score >= 90 else "B" if score >= 75 else "C" if score >= 60 else "D" if score >= 40 else "F"
    return score, letter


def build_dot(domain, hosts_df, findings_df):
    bad = set(findings_df[findings_df["Severidade"].isin(["Crítica", "Alta"])]["Host"]) if not findings_df.empty else set()
    lines = ['digraph G { rankdir=LR; bgcolor="transparent"; '
             'node [shape=box, style="rounded,filled", fontname="Helvetica", fontsize=10, fontcolor="white"]; '
             'edge [color="#9ca3af"];',
             f'"{domain}" [fillcolor="#2563eb"];']
    seen = set()
    for _, r in hosts_df.head(60).iterrows():
        host = r["Host"]
        if host != domain:
            lines.append(f'"{host}" [fillcolor="{"#b91c1c" if host in bad else "#374151"}"];')
            lines.append(f'"{domain}" -> "{host}";')
        elif host in bad:
            lines.append(f'"{domain}" [fillcolor="#b91c1c"];')
        if r["CNAME"]:
            c = r["CNAME"]
            if c not in seen:
                lines.append(f'"{c}" [shape=ellipse, fillcolor="#6d28d9"];')
                seen.add(c)
            lines.append(f'"{host}" -> "{c}" [style=dashed];')
        for ip in [i.strip() for i in r["IPs"].split(",") if i.strip()][:2]:
            if ip not in seen:
                lines.append(f'"{ip}" [shape=ellipse, fillcolor="#047857"];')
                seen.add(ip)
            lines.append(f'"{host}" -> "{ip}";')
    lines.append("}")
    return "\n".join(lines)


def markdown_report(domain, score, letter, hosts_df, findings_df, email_rows, meta):
    L = [f"# Relatório de superfície de ataque — {domain}", "",
         f"- Data (UTC): {meta['data']}", f"- Fonte de subdomínios: {meta['fonte']}",
         f"- Hosts analisados: {len(hosts_df)}  |  Nota de exposição: {score}/100 ({letter})", "",
         "> Auditoria passiva/leve. Os resultados indicam configurações a revisar e devem ser validados manualmente.", ""]
    for sev in SEV_ORDER:
        sub = findings_df[findings_df["Severidade"] == sev]
        if sub.empty:
            continue
        L += [f"## {sev} ({len(sub)})", ""]
        for _, f in sub.iterrows():
            L += [f"### {f['Achado']} — `{f['Host']}`", f"- Categoria: {f['Categoria']}"]
            if f["Evidência"]:
                L.append(f"- Evidência: {f['Evidência']}")
            L += [f"- Recomendação: {f['Recomendação']}", ""]
    L += ["## E-mail e DNS", "", "| Controle | Status | Detalhe |", "|---|---|---|"]
    for r in email_rows:
        L.append(f"| {r['Controle']} | {r['Status']} | {str(r['Detalhe']).replace('|', '/')} |")
    return "\n".join(L)


# ============================================================================
# Interface
# ============================================================================
st.title("🛰️ Attack Surface Mapper")
st.caption("Mapeamento de superfície de ataque e auditoria passiva de configuração.")

pw = secret("APP_PASSWORD")
if pw and not st.session_state.get("auth"):
    entered = st.text_input("Senha de acesso", type="password")
    if entered:
        if hmac.compare_digest(entered, str(pw)):
            st.session_state["auth"] = True
            st.rerun()
        else:
            st.error("Senha incorreta.")
    st.stop()

st.warning(
    "Use apenas em domínios **seus** ou com **autorização escrita** do responsável. "
    "Testar sistemas de terceiros sem permissão é crime (Lei 12.737/2012; art. 154-A do Código Penal). "
    "A ferramenta não explora falhas, não faz força bruta e não varre portas."
)

with st.sidebar:
    st.header("Alvo")
    target = st.text_input("Domínio", placeholder="exemplo.com.br")
    max_hosts = st.slider("Máximo de hosts analisados", 10, 150, 60, step=10)
    do_tests = st.checkbox("Testes leves de CORS e métodos HTTP", value=True)
    do_files = st.checkbox("Verificar arquivos expostos (.git, .env…)", value=True)
    authorized = st.checkbox("Confirmo que tenho autorização para auditar este domínio")
    run = st.button("🚀 Iniciar análise", type="primary", use_container_width=True)
    st.caption("Dica: deixe o app privado em Settings → Sharing, ou defina APP_PASSWORD em Secrets.")

if run:
    domain = clean_domain(target)
    if not DOMAIN_RE.match(domain):
        st.error("Informe um domínio válido, por exemplo: exemplo.com.br")
    elif not authorized:
        st.error("Marque a confirmação de autorização para continuar.")
    else:
        findings, meta = [], {"fonte": "", "data": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")}
        with st.status(f"Analisando {domain}…", expanded=True) as status:
            st.write("1/4 Certificate Transparency…")
            try:
                subs, meta["fonte"] = ct_lookup(domain)
            except Exception as e:  # noqa: BLE001
                subs, meta["fonte"] = [], f"indisponível ({e})"
                st.write(f"⚠️ Não foi possível consultar CT: {e}. Analisando só o domínio principal e www.")
            hosts = [domain, f"www.{domain}"] + [s for s in subs if s not in (domain, f"www.{domain}")]
            if len(hosts) > max_hosts:
                st.write(f"⚠️ {len(hosts)} nomes encontrados; analisando os primeiros {max_hosts}.")
                hosts = hosts[:max_hosts]
            st.write(f"{len(subs)} nomes via {meta['fonte']}. Hosts na análise: {len(hosts)}.")

            st.write("2/4 Resolvendo DNS…")
            bar = st.progress(0.0)
            dns_info = {}
            with ThreadPoolExecutor(max_workers=12) as ex:
                futs = {ex.submit(resolve_host, h): h for h in hosts}
                for i, f in enumerate(as_completed(futs), 1):
                    dns_info[futs[f]] = f.result()
                    bar.progress(i / len(hosts))
            live = [h for h in hosts if dns_info[h]["a"] or dns_info[h]["aaaa"]]
            dead = [h for h in hosts if h not in live]
            for h in dead:
                check_takeover(h, dns_info[h], "", findings)

            st.write(f"3/4 Auditando {len(live)} hosts ativos…")
            bar = st.progress(0.0)
            host_rows = []
            if live:
                with ThreadPoolExecutor(max_workers=8) as ex:
                    futs = {ex.submit(probe_host, h, dns_info[h], do_tests, do_files): h for h in live}
                    for i, f in enumerate(as_completed(futs), 1):
                        row, fnd, _ = f.result()
                        host_rows.append(row)
                        findings.extend(fnd)
                        bar.progress(i / len(live))
            for h in dead:
                d = dns_info[h]
                host_rows.append({"Host": h, "Status": "sem DNS", "URL final": "", "Título": "", "Servidor": "",
                                  "Tecnologias": "", "TLS": "", "IPs": "", "CNAME": d["cname"]})

            st.write("4/4 Auditoria de e-mail e DNS…")
            email_rows = email_audit(domain, findings)
            status.update(label="Análise concluída", state="complete", expanded=False)

        hosts_df = pd.DataFrame(host_rows)
        hosts_df["Achados"] = hosts_df["Host"].map(lambda h: sum(1 for f in findings if f["Host"] == h))
        hosts_df = hosts_df.sort_values(["Status", "Host"], key=lambda s: s.astype(str)).reset_index(drop=True)
        fdf = pd.DataFrame(findings, columns=["Severidade", "Host", "Categoria", "Achado", "Evidência", "Recomendação"])
        if not fdf.empty:
            fdf["_o"] = fdf["Severidade"].map(SEV_ORDER)
            fdf = fdf.drop_duplicates(["Severidade", "Host", "Achado", "Evidência"]).sort_values(["_o", "Host"]).drop(columns="_o")
            fdf = fdf.reset_index(drop=True)
        st.session_state["scan"] = {"domain": domain, "hosts": hosts_df, "findings": fdf,
                                    "email": pd.DataFrame(email_rows), "meta": meta,
                                    "discovered": len(subs), "live": len(live)}

scan = st.session_state.get("scan")
if not scan:
    st.info("Informe o domínio na barra lateral, confirme a autorização e inicie a análise.")
    st.stop()

domain, hosts_df, fdf, edf = scan["domain"], scan["hosts"], scan["findings"], scan["email"]
score, letter = grade(fdf.to_dict("records"))

st.subheader(f"Resultado: {domain}")
c1, c2, c3, c4, c5 = st.columns(5)
c1.metric("Nomes descobertos", scan["discovered"])
c2.metric("Hosts ativos", scan["live"])
c3.metric("Críticos/Altos", int(fdf["Severidade"].isin(["Crítica", "Alta"]).sum()) if not fdf.empty else 0)
c4.metric("Total de achados", len(fdf))
c5.metric("Nota de exposição", f"{score}/100 ({letter})")

tab1, tab2, tab3, tab4, tab5 = st.tabs(["Achados", "Hosts", "Grafo", "E-mail/DNS", "Exportar"])

with tab1:
    if fdf.empty:
        st.success("Nenhum achado nas verificações realizadas. Isso não garante ausência de falhas.")
    else:
        sel = st.multiselect("Severidade", list(SEV_ORDER), default=["Crítica", "Alta", "Média", "Baixa"])
        view = fdf[fdf["Severidade"].isin(sel)].copy()
        view["Severidade"] = view["Severidade"].map(lambda s: f"{SEV_EMOJI[s]} {s}")
        st.dataframe(view, use_container_width=True, hide_index=True)
        st.caption("Achados são indícios de configuração a revisar; valide manualmente antes de agir.")

with tab2:
    st.dataframe(hosts_df, use_container_width=True, hide_index=True)

with tab3:
    st.graphviz_chart(build_dot(domain, hosts_df, fdf), use_container_width=True)
    st.caption("Azul: domínio · Vermelho: host com achado Alto/Crítico · Roxo: destino CNAME · Verde: IP")

with tab4:
    st.dataframe(edf, use_container_width=True, hide_index=True)

with tab5:
    md = markdown_report(domain, score, letter, hosts_df, fdf, edf.to_dict("records"), scan["meta"])
    st.download_button("⬇️ Relatório (Markdown)", md.encode("utf-8"), file_name=f"relatorio_{domain}.md",
                       mime="text/markdown")
    st.download_button("⬇️ Achados (CSV)", fdf.to_csv(index=False).encode("utf-8-sig"),
                       file_name=f"achados_{domain}.csv", mime="text/csv")
    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as w:
        fdf.to_excel(w, index=False, sheet_name="Achados")
        hosts_df.to_excel(w, index=False, sheet_name="Hosts")
        edf.to_excel(w, index=False, sheet_name="Email-DNS")
    st.download_button("⬇️ Planilha (Excel)", buf.getvalue(), file_name=f"auditoria_{domain}.xlsx",
                       mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet")
