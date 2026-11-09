"""
Mass Attack Surface Scanner + Vulnerability Auditor by DellSouX
===================================================
Varre múltiplos domínios simultaneamente a partir de uma lista fornecida,
identificando e isolando de forma automatizada apenas aqueles que apresentam
falhas críticas, de e-mail (DMARC/SPF), arquivos expostos ou TLS.
"""
import html as htmllib
import io
import re
import socket
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import dns.resolver
import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="Mass Vulnerability Scanner", page_icon="📡", layout="wide")

UA = "MassScanner/2.0 (auditoria autorizada)"
HTTP_TIMEOUT = 5
MAX_BODY = 100_000

SEV_ORDER = {"Crítica": 0, "Alta": 1, "Média": 2, "Baixa": 3, "Info": 4}
SEV_EMOJI = {"Crítica": "🔴", "Alta": "🟠", "Média": "🟡", "Baixa": "🔵", "Info": "⚪"}

# Regex para limpar e validar múltiplos domínios
DOMAIN_RE = re.compile(r"^(?=.{4,253}$)([a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")

def clean_domain(value):
    v = (value or "").strip().lower()
    v = re.sub(r"^https?://", "", v)
    v = v.split("/")[0].split(":")[0].strip(".")
    return v.removeprefix("www.")

def dns_query(name, rtype):
    r = dns.resolver.Resolver()
    r.nameservers = ["1.1.1.1", "8.8.8.8"]
    r.timeout, r.lifetime = 2, 3
    try:
        ans = r.resolve(name, rtype)
        return [a.to_text() for a in ans]
    except Exception:
        return []

def check_security_headers(headers):
    h = {k.lower(): v for k, v in headers.items()}
    missing = []
    if "strict-transport-security" not in h:
        missing.append("HSTS")
    if "content-security-policy" not in h:
        missing.append("CSP")
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", "").lower():
        missing.append("X-Frame-Options")
    return missing

def audit_target(domain):
    """Executa a auditoria rápida focada em encontrar falhas em um domínio específico."""
    findings = []
    
    # 1. Auditoria de E-mail (DMARC e SPF)
    mx = dns_query(domain, "MX")
    has_mx = bool(mx) and mx != ["0 ."]
    
    if has_mx:
        txt_records = dns_query(domain, "TXT")
        # Verificar SPF
        spf = [r.strip('"') for r in txt_records if r.strip('"').lower().startswith("v=spf1")]
        if not spf:
            findings.append({"Severidade": "Alta", "Host": domain, "Categoria": "E-mail", "Achado": "SPF Ausente", "Detalhe": "Domínio envia e-mails mas não restringe IPs autorizados."})
        
        # Verificar DMARC
        dmarc = [r.strip('"') for r in dns_query(f"_dmarc.{domain}", "TXT") if r.strip('"').lower().startswith("v=dmarc1")]
        if not dmarc:
            findings.append({"Severidade": "Alta", "Host": domain, "Categoria": "E-mail", "Achado": "DMARC Ausente", "Detalhe": "Proteção anti-spoofing/phishing desativada."})
        elif "p=none" in dmarc[0].lower():
            findings.append({"Severidade": "Média", "Host": domain, "Categoria": "E-mail", "Achado": "DMARC em modo monitoramento (p=none)", "Detalhe": "Não bloqueia e-mails falsificados."})

    # 2. Auditoria HTTP/TLS e Cabeçalhos
    resp = None
    protocols = ["https://", "http://"]
    for proto in protocols:
        try:
            resp = requests.get(f"{proto}{domain}/", headers={"User-Agent": UA}, timeout=HTTP_TIMEOUT, allow_redirects=True, verify=False)
            break
        except Exception:
            continue
            
    if resp is not None:
        # Verificar cabeçalhos de segurança
        missing_hdrs = check_security_headers(resp.headers)
        if missing_hdrs:
            findings.append({"Severidade": "Baixa", "Host": domain, "Categoria": "Headers", "Achado": "Cabeçalhos ausentes", "Detalhe": f"Faltando: {', '.join(missing_hdrs)}"})
        
        # Verificar arquivos expostos (.env básico)
        try:
            env_resp = requests.get(f"https://{domain}/.env", headers={"User-Agent": UA}, timeout=3, verify=False)
            if env_resp.status_code == 200 and ("DB_" in env_resp.text or "APP_" in env_resp.text):
                findings.append({"Severidade": "Crítica", "Host": domain, "Categoria": "Vazamento", "Achado": "Arquivo .env exposto!", "Detalhe": f"Credenciais expostas publicamente."})
        except Exception:
            pass
            
    return findings

# --- INTERFACE STREAMLIT ---
st.title("📡 Mass Vulnerability Scanner")
st.caption("Insira uma lista de domínios para varrer a internet atrás de falhas de configuração em massa.")

st.warning("Atenção: Garanta que possui escopo ou permissão legal para os alvos listados.")

# Área de entrada para múltiplos alvos
input_mode = st.radio("Como deseja inserir os alvos?", ["Digitar/Colar Lista", "Carregar arquivo .txt"])
raw_domains = []

if input_mode == "Digitar/Colar Lista":
    text_input = st.text_area("Insira um domínio por linha:", placeholder="exemplo1.com\nexemplo2.com.br", height=200)
    raw_domains = text_input.split("\n")
else:
    uploaded_file = st.file_uploader("Selecione um arquivo de texto (.txt)", type=["txt"])
    if uploaded_file is not None:
        raw_domains = io.StringIO(uploaded_file.getvalue().decode("utf-8")).read().split("\n")

# Filtra e higieniza a lista de entrada
targets = sorted(list({clean_domain(d) for d in raw_domains if clean_domain(d) and DOMAIN_RE.match(clean_domain(d))}))

st.sidebar.header("Configurações da Varredura")
max_threads = st.sidebar.slider("Threads Simultâneas (Velocidade)", 5, 50, 20)
authorized = st.sidebar.checkbox("Possuo autorização para validar estes alvos")
run_btn = st.sidebar.button("🚀 Iniciar Varredura em Massa", type="primary", use_container_width=True)

if run_btn:
    if not targets:
        st.error("Adicione pelo menos um domínio válido para iniciar.")
    elif not authorized:
        st.error("Você precisa confirmar a autorização na barra lateral.")
    else:
        all_findings = []
        total_targets = len(targets)
        
        status_box = st.status(f"Processando {total_targets} alvos em paralelo...", expanded=True)
        with status_box:
            progress_bar = st.progress(0.0)
            
            # Execução assíncrona escalável em massa
            with ThreadPoolExecutor(max_workers=max_threads) as executor:
                future_to_domain = {executor.submit(audit_target, domain): domain for domain in targets}
                
                for idx, future in enumerate(as_completed(future_to_domain), 1):
                    domain = future_to_domain[future]
                    try:
                        result = future.result()
                        if result:
                            all_findings.extend(result)
                    except Exception as e:
                        st.write(f"⚠️ Erro ao escanear {domain}: {str(e)}")
                    
                    progress_bar.progress(idx / total_targets)
            
            status_box.update(label="Varredura concluída!", state="complete", expanded=False)
        
        # --- EXIBIÇÃO DOS RESULTADOS FILTRADOS ---
        st.subheader("🛑 Alvos com Falhas Encontradas")
        
        if not all_findings:
            st.success("Excelente! Nenhum dos domínios testados apresentou as falhas mapeadas.")
        else:
            df = pd.DataFrame(all_findings)
            df["_ordem"] = df["Severidade"].map(SEV_ORDER)
            df = df.sort_values("_ordem").drop(columns=["_ordem"]).reset_index(drop=True)
            
            # Filtro visual rápido por severidade
            selected_sev = st.multiselect("Filtrar por Severidade:", list(SEV_ORDER.keys()), default=list(SEV_ORDER.keys()))
            view_df = df[df["Severidade"].isin(selected_sev)].copy()
            view_df["Severidade"] = view_df["Severidade"].map(lambda s: f"{SEV_EMOJI.get(s, '⚪')} {s}")
            
            # Métricas rápidas
            c1, c2, c3 = st.columns(3)
            c1.metric("Total de Domínios Analisados", total_targets)
            c2.metric("Domínios Vulneráveis Detectados", view_df["Host"].nunique())
            c3.metric("Total de Falhas Isoladas", len(view_df))
            
            st.dataframe(view_df, use_container_width=True, hide_index=True)
            
            # Opção de exportação da lista negra de falhas
            st.download_button("⬇️ Baixar Relatório de Falhas (CSV)", df.to_csv(index=False).encode("utf-8-sig"),
                               file_name="mass_scan_vulnerabilities.csv", mime="text/csv")
