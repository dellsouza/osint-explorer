"""
OSINT Explorer v2
Pesquisa de informações publicamente acessíveis a partir de nome, usando dorks por plataforma.

Provedores (usa o primeiro disponível):
  1. Serper.dev  -> st.secrets["SERPER_API_KEY"]  (Google real)
  2. Brave API   -> st.secrets["BRAVE_API_KEY"]
  3. DuckDuckGo  -> sem chave (pode ser bloqueado em servidores de nuvem)
"""
import io
import re
import time
import unicodedata
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse

import pandas as pd
import requests
import streamlit as st

st.set_page_config(page_title="OSINT Explorer", page_icon="🔎", layout="wide")

# ----------------------------------------------------------------------------
# Configuração
# ----------------------------------------------------------------------------
PLATFORMS = {
    "Instagram": {"site": "instagram.com", "hosts": ("instagram.com",), "cat": "Rede social"},
    "Facebook": {"site": "facebook.com", "hosts": ("facebook.com",), "cat": "Rede social"},
    "LinkedIn": {"site": "linkedin.com/in", "hosts": ("linkedin.com",), "cat": "Profissional"},
    "X / Twitter": {"site": "x.com", "hosts": ("x.com", "twitter.com"), "cat": "Rede social"},
    "TikTok": {"site": "tiktok.com", "hosts": ("tiktok.com",), "cat": "Rede social"},
    "YouTube": {"site": "youtube.com", "hosts": ("youtube.com", "youtu.be"), "cat": "Mídia"},
    "GitHub": {"site": "github.com", "hosts": ("github.com",), "cat": "Tecnologia"},
    "Lattes": {"site": "lattes.cnpq.br", "hosts": ("lattes.cnpq.br",), "cat": "Acadêmico"},
    "Gov.br": {"site": "gov.br", "hosts": ("gov.br",), "cat": "Institucional"},
}
DEFAULT_PLATFORMS = ["Instagram", "Facebook", "LinkedIn", "X / Twitter", "YouTube", "GitHub"]
PARTICLES = {"de", "da", "do", "dos", "das", "e"}
CACHE_TTL = 3600  # segundos
TIMEOUT = 15


# ----------------------------------------------------------------------------
# Utilidades de texto e URL
# ----------------------------------------------------------------------------
def norm(value):
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = "".join(c for c in value if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", value.lower()).strip()


def name_tokens(full_name):
    return [t for t in norm(full_name).split() if t not in PARTICLES]


def strip_html(text):
    return re.sub(r"<[^>]+>", "", text or "")


def clean_host(host):
    host = host.lower()
    return re.sub(r"^(www|m|mobile|web|pt-br|br)\.", "", host)


def clean_url(url):
    p = urlparse(url)
    query = p.query if p.path.endswith("profile.php") else ""
    return urlunparse((p.scheme.lower(), clean_host(p.netloc), p.path.rstrip("/"), "", query, ""))


def platform_of(url):
    host = clean_host(urlparse(url).netloc)
    for label, cfg in PLATFORMS.items():
        for h in cfg["hosts"]:
            if host == h or host.endswith("." + h):
                return label
    return "Web"


def category_of(platform):
    return PLATFORMS.get(platform, {}).get("cat", "Web / Notícias")


def page_kind(url):
    """Classifica a URL: Perfil/Canal (provável) ou Post/Outro. Heurística simples."""
    p = urlparse(url)
    host = clean_host(p.netloc)
    parts = [s for s in p.path.split("/") if s]
    if not parts:
        return "Página"

    if host.endswith("instagram.com"):
        bad = {"explore", "reel", "reels", "p", "tv", "accounts", "stories", "directory"}
        return "Perfil" if len(parts) == 1 and parts[0] not in bad else "Post/Outro"
    if host.endswith("facebook.com"):
        bad = {"public", "people", "groups", "watch", "events", "marketplace", "pages",
               "photo", "photos", "posts", "videos", "reel", "share", "hashtag"}
        if parts[0] == "profile.php":
            return "Perfil"
        return "Perfil" if len(parts) == 1 and parts[0] not in bad else "Post/Outro"
    if host.endswith("linkedin.com"):
        return "Perfil" if parts[0] == "in" and len(parts) >= 2 else "Post/Outro"
    if host in ("x.com", "twitter.com"):
        bad = {"search", "hashtag", "i", "home", "explore", "intent"}
        return "Perfil" if len(parts) == 1 and parts[0] not in bad else "Post/Outro"
    if host.endswith("tiktok.com"):
        return "Perfil" if parts[0].startswith("@") and len(parts) == 1 else "Post/Outro"
    if host.endswith("github.com"):
        return "Perfil" if len(parts) == 1 else "Repositório/Outro"
    if host.endswith("youtube.com"):
        if parts[0].startswith("@") or parts[0] in ("channel", "c", "user"):
            return "Canal"
        return "Vídeo/Outro"
    return "Página"


def handle_of(url):
    parts = [s for s in urlparse(url).path.split("/") if s]
    if not parts:
        return ""
    if parts[0] in ("in", "channel", "c", "user") and len(parts) > 1:
        return parts[1]
    return parts[0].lstrip("@")


# ----------------------------------------------------------------------------
# Pontuação textual (NÃO confirma identidade)
# ----------------------------------------------------------------------------
def score_row(title, snippet, url, kind, full_name, context, city):
    """Retorna pontuação 0-10 de correspondência textual."""
    text = norm(f"{title} {snippet}")
    words = set(re.findall(r"\w+", text))
    name = norm(full_name)
    tokens = name_tokens(full_name)
    pts = 0.0

    if name and name in text:
        pts += 4
    if tokens:
        ratio = sum(1 for t in tokens if t in words) / len(tokens)
        pts += round(3 * ratio)

    if kind in ("Perfil", "Canal") and tokens:
        handle = re.sub(r"[^a-z]", "", norm(handle_of(url)))
        if handle:
            if all(t in handle for t in (tokens[0], tokens[-1])):
                pts += 2
            elif tokens[0] in handle or tokens[-1] in handle:
                pts += 1

    if context and norm(context) in text:
        pts += 1
    if city and norm(city) in text:
        pts += 1
    return int(min(pts, 10))


def band(n):
    return "Alta" if n >= 8 else ("Média" if n >= 5 else "Baixa")


# ----------------------------------------------------------------------------
# Provedores de busca
# ----------------------------------------------------------------------------
def secret(key):
    try:
        return st.secrets.get(key)
    except Exception:
        return None


def pick_provider():
    if secret("SERPER_API_KEY"):
        return "serper"
    if secret("BRAVE_API_KEY"):
        return "brave"
    return "ddgs"


PROVIDER_LABEL = {
    "serper": "Serper.dev (Google)",
    "brave": "Brave Search API",
    "ddgs": "DuckDuckGo (sem chave — pode ser bloqueado na nuvem)",
}


def _serper(query, n, key):
    r = requests.post(
        "https://google.serper.dev/search",
        headers={"X-API-KEY": key, "Content-Type": "application/json"},
        json={"q": query, "gl": "br", "hl": "pt-br", "num": n},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    return [
        {"title": x.get("title", ""), "url": x.get("link", ""), "snippet": x.get("snippet", "")}
        for x in r.json().get("organic", [])
    ]


def _brave(query, n, key):
    r = requests.get(
        "https://api.search.brave.com/res/v1/web/search",
        headers={"X-Subscription-Token": key, "Accept": "application/json"},
        params={"q": query, "count": min(n, 20), "country": "BR", "search_lang": "pt"},
        timeout=TIMEOUT,
    )
    r.raise_for_status()
    results = r.json().get("web", {}).get("results", [])
    return [
        {"title": strip_html(x.get("title", "")), "url": x.get("url", ""),
         "snippet": strip_html(x.get("description", ""))}
        for x in results
    ]


def _ddgs(query, n):
    from ddgs import DDGS
    last = None
    for attempt in range(3):
        try:
            rows = DDGS().text(query, region="br-pt", max_results=n)
            return [
                {"title": r.get("title", ""), "url": r.get("href", ""), "snippet": r.get("body", "")}
                for r in rows
            ]
        except Exception as e:  # noqa: BLE001
            if "no results" in str(e).lower():
                return []
            last = e
            time.sleep(1.5 * (attempt + 1))
    raise last


@st.cache_resource
def get_cache():
    return {}


CACHE = get_cache()


def search(provider, query, n):
    """Retorna (hits, erro, veio_do_cache). Seguro para uso em threads (sem chamadas st.*)."""
    key = (provider, query, n)
    hit = CACHE.get(key)
    if hit and time.time() - hit[0] < CACHE_TTL:
        return hit[1], None, True
    try:
        if provider == "serper":
            hits = _serper(query, n, secret("SERPER_API_KEY"))
        elif provider == "brave":
            hits = _brave(query, n, secret("BRAVE_API_KEY"))
        else:
            hits = _ddgs(query, n)
            time.sleep(1.0)  # evita rate limit no DuckDuckGo
        CACHE[key] = (time.time(), hits)
        return hits, None, False
    except Exception as e:  # noqa: BLE001
        return [], f"{type(e).__name__}: {e}", False


# ----------------------------------------------------------------------------
# Construção das consultas (dorks)
# ----------------------------------------------------------------------------
def build_queries(name, platforms, context, city, include_news):
    queries = [("Geral", f'"{name}"')]
    for p in platforms:
        queries.append((p, f'site:{PLATFORMS[p]["site"]} "{name}"'))
    if context:
        queries.append(("Contexto", f'"{name}" "{context}"'))
    if city:
        queries.append(("Região", f'"{name}" "{city}"'))
    if include_news:
        queries.append(("Notícias", f'"{name}" notícias'))
    return queries


# ----------------------------------------------------------------------------
# Interface
# ----------------------------------------------------------------------------
st.title("🔎 OSINT Explorer")
st.caption("Pesquisa e organização de informações publicamente acessíveis — com revisão humana.")
st.warning(
    "Use apenas para finalidades legítimas e em conformidade com a LGPD. Não pesquise dados privados, "
    "endereços residenciais, documentos, credenciais ou informações sensíveis. Resultados por nome podem "
    "pertencer a homônimos. A pontuação mede correspondência textual e **não confirma identidade**."
)

if "investigations" not in st.session_state:
    st.session_state.investigations = []

with st.sidebar:
    st.header("Nova pesquisa")
    full_name = st.text_input("Nome completo", placeholder="Nome e sobrenome")
    context = st.text_input("Contexto público (opcional)", placeholder="Profissão, organização, projeto")
    city = st.text_input("Cidade/região (opcional)", placeholder="Somente se relevante")
    platforms = st.multiselect("Plataformas", list(PLATFORMS), default=DEFAULT_PLATFORMS)
    include_news = st.checkbox("Incluir busca de notícias", value=True)
    max_results = st.selectbox("Resultados por consulta", [5, 10, 20], index=1)
    run = st.button("🔍 Pesquisar", type="primary", use_container_width=True)
    st.divider()
    st.caption(f"Motor de busca: **{PROVIDER_LABEL[pick_provider()]}**")
    st.caption("As pesquisas ficam apenas na sessão atual. Não há banco de dados nesta versão.")

if run:
    name = " ".join(full_name.split())
    if len(name.split()) < 2:
        st.error("Informe pelo menos nome e sobrenome.")
    else:
        provider = pick_provider()
        queries = build_queries(name, platforms, context.strip(), city.strip(), include_news)
        workers = 1 if provider == "ddgs" else 4

        rows, log = [], []
        bar = st.progress(0, text="Preparando consultas…")
        with ThreadPoolExecutor(max_workers=workers) as ex:
            futures = {ex.submit(search, provider, q, max_results): (label, q) for label, q in queries}
            for i, fut in enumerate(as_completed(futures), start=1):
                label, q = futures[fut]
                hits, err, cached = fut.result()
                log.append({"Grupo": label, "Consulta": q, "Resultados": len(hits),
                            "Cache": "sim" if cached else "não", "Erro": err or ""})
                for h in hits:
                    url = h.get("url", "")
                    if not url.startswith("http"):
                        continue
                    plat = platform_of(url)
                    kind = page_kind(url)
                    pts = score_row(h["title"], h["snippet"], url, kind, name, context, city)
                    rows.append({
                        "Plataforma": plat,
                        "Tipo": kind,
                        "Título": h["title"],
                        "Descrição": h["snippet"],
                        "Relevância": pts,
                        "Faixa": band(pts),
                        "Categoria": category_of(plat),
                        "Domínio": clean_host(urlparse(url).netloc),
                        "URL": url,
                        "Consulta": q,
                    })
                bar.progress(i / len(queries), text=f"Consultando {i}/{len(queries)}")
        bar.empty()

        errors = [x for x in log if x["Erro"]]
        if errors and len(errors) == len(log):
            st.error(
                "Todas as consultas falharam. Veja o diagnóstico abaixo. "
                "Se o motor for DuckDuckGo, provavelmente o IP do servidor está bloqueado: "
                "configure SERPER_API_KEY ou BRAVE_API_KEY em Secrets."
            )
        elif errors:
            st.warning(f"{len(errors)} de {len(log)} consultas falharam. Veja o diagnóstico abaixo.")

        if rows:
            df = pd.DataFrame(rows)
            df["_k"] = df["URL"].map(clean_url)
            df = (df.sort_values("Relevância", ascending=False)
                    .drop_duplicates("_k").drop(columns="_k").reset_index(drop=True))
            st.session_state.investigations.insert(0, {
                "id": datetime.now().strftime("%Y%m%d%H%M%S"),
                "nome": name, "contexto": context, "cidade": city,
                "data": datetime.now(timezone.utc).isoformat(),
                "provider": PROVIDER_LABEL[provider],
                "dataframe": df, "log": pd.DataFrame(log),
            })
            st.success(f"Pesquisa concluída: {len(df)} páginas únicas.")
        else:
            st.session_state.investigations.insert(0, {
                "id": datetime.now().strftime("%Y%m%d%H%M%S"),
                "nome": name, "contexto": context, "cidade": city,
                "data": datetime.now(timezone.utc).isoformat(),
                "provider": PROVIDER_LABEL[provider],
                "dataframe": pd.DataFrame(columns=[
                    "Plataforma", "Tipo", "Título", "Descrição", "Relevância", "Faixa",
                    "Categoria", "Domínio", "URL", "Consulta"]),
                "log": pd.DataFrame(log),
            })
            st.warning("Nenhum resultado retornado. Veja o diagnóstico abaixo.")

st.subheader("Pesquisas desta sessão")
if not st.session_state.investigations:
    st.info("Faça uma pesquisa pelo painel à esquerda para começar.")
else:
    labels = [f"{x['nome']} — {x['data'][:19].replace('T', ' ')}" for x in st.session_state.investigations]
    selected = st.selectbox("Selecione uma pesquisa", range(len(labels)), format_func=lambda i: labels[i])
    item = st.session_state.investigations[selected]
    df = item["dataframe"].copy()

    with st.expander("🛠️ Diagnóstico das consultas", expanded=df.empty):
        st.caption(f"Motor usado: {item['provider']}")
        st.dataframe(item["log"], use_container_width=True, hide_index=True)

    if df.empty:
        st.stop()

    c1, c2, c3, c4 = st.columns(4)
    c1.metric("Páginas únicas", len(df))
    c2.metric("Perfis prováveis", int(df["Tipo"].isin(["Perfil", "Canal"]).sum()))
    c3.metric("Domínios", df["Domínio"].nunique())
    c4.metric("Relevância Alta", int((df["Faixa"] == "Alta").sum()))

    f1, f2, f3 = st.columns([2, 1, 1])
    plat_sel = f1.multiselect("Plataformas", sorted(df["Plataforma"].unique()),
                              default=sorted(df["Plataforma"].unique()))
    only_profiles = f2.checkbox("Somente perfis/canais", value=False)
    min_score = f3.slider("Relevância mínima", 0, 10, 0)

    view = df[df["Plataforma"].isin(plat_sel) & (df["Relevância"] >= min_score)]
    if only_profiles:
        view = view[view["Tipo"].isin(["Perfil", "Canal"])]

    st.caption("A recorrência de um domínio não é confirmação independente: páginas podem replicar a mesma informação.")
    st.dataframe(
        view[["Plataforma", "Tipo", "Título", "Descrição", "Relevância", "Faixa", "URL"]],
        use_container_width=True, hide_index=True,
        column_config={"URL": st.column_config.LinkColumn("URL", display_text="abrir")},
    )

    st.markdown("#### Resumo por plataforma")
    summary = (df.groupby(["Plataforma", "Categoria"])
                 .agg(Páginas=("URL", "size"), Perfis=("Tipo", lambda s: int(s.isin(["Perfil", "Canal"]).sum())),
                      Melhor_relevância=("Relevância", "max"))
                 .reset_index().sort_values("Páginas", ascending=False))
    st.dataframe(summary, use_container_width=True, hide_index=True)

    csv = view.to_csv(index=False).encode("utf-8-sig")
    st.download_button("⬇️ Baixar CSV (filtrado)", csv, file_name="osint_resultados.csv", mime="text/csv")

    buf = io.BytesIO()
    with pd.ExcelWriter(buf, engine="openpyxl") as writer:
        view.to_excel(writer, index=False, sheet_name="Resultados")
        summary.to_excel(writer, index=False, sheet_name="Plataformas")
        item["log"].to_excel(writer, index=False, sheet_name="Consultas")
        pd.DataFrame([{
            "Nome pesquisado": item["nome"], "Contexto": item["contexto"], "Região": item["cidade"],
            "Data UTC": item["data"], "Motor": item["provider"],
            "Nota": "Relevância textual não confirma identidade.",
        }]).to_excel(writer, index=False, sheet_name="Resumo")
    st.download_button(
        "⬇️ Baixar Excel", buf.getvalue(), file_name="osint_relatorio.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    )

    if st.button("Remover esta pesquisa da sessão"):
        st.session_state.investigations.pop(selected)
        st.rerun()
