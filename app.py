import streamlit as st
import pandas as pd
import re, io, json, time
from datetime import datetime, timezone
from urllib.parse import urlparse, urlunparse
from collections import Counter
from ddgs import DDGS

st.set_page_config(page_title="OSINT Explorer", page_icon="🔎", layout="wide")

st.title("🔎 OSINT Explorer")
st.caption("Pesquisa e organização de informações publicamente acessíveis — com revisão humana.")

st.warning(
    "Use apenas para finalidades legítimas. Não pesquise dados privados, endereços residenciais, "
    "documentos, credenciais ou informações sensíveis. Resultados por nome podem pertencer a homônimos. "
    "A pontuação abaixo mede correspondência textual, não confirma identidade."
)

def norm(value):
    import unicodedata
    value = unicodedata.normalize("NFKD", str(value or ""))
    value = "".join(c for c in value if not unicodedata.combining(c))
    return re.sub(r"\s+", " ", value.lower()).strip()

def clean_url(url):
    p = urlparse(url)
    return urlunparse((p.scheme.lower(), p.netloc.lower().removeprefix("www."),
                       p.path.rstrip("/"), "", "", ""))

def category(url):
    host = urlparse(url).netloc.lower().removeprefix("www.")
    mapping = {
        "linkedin.com": "Profissional",
        "github.com": "Tecnologia",
        "youtube.com": "Mídia",
        "youtu.be": "Mídia",
        "instagram.com": "Rede social pública",
        "facebook.com": "Rede social pública",
        "gov.br": "Institucional",
        "jus.br": "Institucional",
        "edu.br": "Acadêmico",
        "lattes.cnpq.br": "Acadêmico",
    }
    for domain, label in mapping.items():
        if host == domain or host.endswith("." + domain):
            return label
    return "Web / Notícias"

def score(row, full_name, context):
    text = norm(f"{row.get('title','')} {row.get('snippet','')}")
    name = norm(full_name)
    terms = name.split()
    points = 5 if name and name in text else 0
    points += min(sum(1 for term in terms if term in text.split()), 3)
    if context and norm(context) in text:
        points += 2
    return points

if "investigations" not in st.session_state:
    st.session_state.investigations = []

with st.sidebar:
    st.header("Nova pesquisa")
    full_name = st.text_input("Nome completo", placeholder="Nome e sobrenome")
    context = st.text_input("Contexto público (opcional)", placeholder="Profissão, organização, projeto")
    city = st.text_input("Cidade/região (opcional)", placeholder="Somente se relevante")
    max_results = st.selectbox("Resultados por consulta", [5, 10, 15], index=1)
    run = st.button("🔍 Pesquisar", type="primary", use_container_width=True)
    st.divider()
    st.caption("As pesquisas ficam apenas na sessão atual do navegador. Não há banco de dados nesta versão.")

if run:
    if len(full_name.split()) < 2:
        st.error("Informe pelo menos nome e sobrenome.")
    else:
        queries = [
            f'"{full_name}"',
            f'"{full_name}" notícias',
            f'"{full_name}" entrevista OR publicação',
            f'"{full_name}" perfil profissional',
            f'"{full_name}" site:linkedin.com/in',
            f'"{full_name}" site:github.com',
            f'"{full_name}" site:gov.br',
        ]
        if context.strip():
            queries += [f'"{full_name}" "{context}"']
        if city.strip():
            queries += [f'"{full_name}" "{city}"']

        collected = []
        progress = st.progress(0, text="Preparando consultas…")
        try:
            with DDGS() as ddgs:
                for i, query in enumerate(queries):
                    try:
                        hits = ddgs.text(query, max_results=max_results)
                        for hit in hits:
                            url = hit.get("href", "")
                            if url.startswith("http"):
                                collected.append({
                                    "Consulta": query,
                                    "Título": hit.get("title", ""),
                                    "Descrição": hit.get("body", ""),
                                    "URL": url,
                                    "Domínio": urlparse(url).netloc.lower().removeprefix("www."),
                                    "Categoria": category(url)
                                })
                    except Exception as e:
                        st.info(f"Uma consulta não retornou resultados: {query}")
                    progress.progress((i + 1) / len(queries), text=f"Consultando {i+1}/{len(queries)}")
                    time.sleep(0.5)
        except Exception as e:
            st.error(f"O serviço de pesquisa não respondeu: {e}")
            collected = []

        if collected:
            df = pd.DataFrame(collected)
            df["URL normalizada"] = df["URL"].apply(clean_url)
            df = df.drop_duplicates(subset=["URL normalizada"]).copy()
            df["Relevância textual"] = df.apply(lambda r: score(
                {"title": r["Título"], "snippet": r["Descrição"]}, full_name, context
            ), axis=1)
            df["Faixa textual"] = df["Relevância textual"].apply(
                lambda n: "Alta" if n >= 9 else ("Intermediária" if n >= 6 else "Baixa")
            )
            record = {
                "id": datetime.now().strftime("%Y%m%d%H%M%S"),
                "nome": full_name,
                "contexto": context,
                "cidade": city,
                "data": datetime.now(timezone.utc).isoformat(),
                "dataframe": df.drop(columns=["URL normalizada"])
            }
            st.session_state.investigations.insert(0, record)
            st.success(f"Pesquisa concluída: {len(df)} páginas únicas.")
        else:
            st.warning("Nenhum resultado foi retornado. O mecanismo de busca pode estar temporariamente indisponível.")

st.subheader("Pesquisas desta sessão")
if not st.session_state.investigations:
    st.info("Faça uma pesquisa pelo painel à esquerda para começar.")
else:
    labels = [
        f"{x['nome']} — {x['data'][:19].replace('T',' ')}"
        for x in st.session_state.investigations
    ]
    selected = st.selectbox("Selecione uma pesquisa", range(len(labels)), format_func=lambda i: labels[i])
    item = st.session_state.investigations[selected]
    df = item["dataframe"].copy()

    c1, c2, c3 = st.columns(3)
    c1.metric("Páginas únicas", len(df))
    c2.metric("Domínios", df["Domínio"].nunique())
    c3.metric("Categorias", df["Categoria"].nunique())

    st.caption("A recorrência de um domínio não é confirmação independente: páginas podem replicar a mesma informação.")
    categories = ["Todas"] + sorted(df["Categoria"].dropna().unique().tolist())
    chosen = st.selectbox("Filtrar categoria", categories)
    view = df if chosen == "Todas" else df[df["Categoria"] == chosen]
    st.dataframe(
        view[["Título", "Descrição", "Categoria", "Relevância textual", "Faixa textual", "Domínio", "URL"]],
        use_container_width=True,
        hide_index=True
    )

    st.markdown("#### Domínios encontrados")
    domains = (df.groupby(["Domínio", "Categoria"]).size()
               .reset_index(name="Páginas").sort_values("Páginas", ascending=False))
    st.dataframe(domains, use_container_width=True, hide_index=True)

    csv = df.to_csv(index=False).encode("utf-8-sig")
    st.download_button("⬇️ Baixar CSV", csv, file_name="osint_resultados.csv", mime="text/csv")

    excel_buffer = io.BytesIO()
    with pd.ExcelWriter(excel_buffer, engine="openpyxl") as writer:
        df.to_excel(writer, index=False, sheet_name="Resultados")
        domains.to_excel(writer, index=False, sheet_name="Dominios")
        pd.DataFrame([{
            "Nome pesquisado": item["nome"],
            "Contexto": item["contexto"],
            "Região": item["cidade"],
            "Data UTC": item["data"],
            "Nota": "Relevância textual não confirma identidade."
        }]).to_excel(writer, index=False, sheet_name="Resumo")
    st.download_button(
        "⬇️ Baixar Excel", excel_buffer.getvalue(),
        file_name="osint_relatorio.xlsx",
        mime="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"
    )

    if st.button("Remover esta pesquisa da sessão"):
        st.session_state.investigations.pop(selected)
        st.rerun()
