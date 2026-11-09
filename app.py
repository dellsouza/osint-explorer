"""
Defensive Google Dorking Generator
==================================
Mapeia se a infraestrutura de um domínio específico está vazando dados
confidenciais para os índices públicos de motores de busca.
"""
from urllib.parse import quote_plus
import pandas as pd
import streamlit as st

st.set_page_config(page_title="Defensive Dorking Audit", page_icon="🔍", layout="wide")

st.title("🔍 Defensive Google Dorking Generator by DellSoux")
st.caption("Verifique o que os motores de busca indexaram a respeito da sua própria infraestrutura.")

# Interface de Entrada
with st.sidebar:
    st.header("Escopo da Auditoria")
    meu_dominio = st.text_input("Seu Domínio:", placeholder="exemplo.com.br")
    confirmacao = st.checkbox("Confirmo que sou dono ou possuo autorização para auditar este domínio")
    gerar_btn = st.button("Gerar Matriz de Varredura", type="primary", use_container_width=True)

if gerar_btn:
    if not meu_dominio.strip():
        st.error("Insira um domínio válido.")
    elif not confirmacao:
        st.error("Você deve confirmar a autorização do escopo.")
    else:
        dominio_limpo = meu_dominio.strip().lower().replace("https://", "").replace("http://", "").split("/")[0]
        
        # Estruturação da matriz de testes defensivos baseados no GHDB (Google Hacking Database)
        matriz_dorks = [
            {
                "Categoria": "Arquivos de Configuração / Ambientes",
                "Objetivo": "Verificar se arquivos .env ou configurações de sistemas modernos estão expostos",
                "Query": f"site:{dominio_limpo} filetype:env OR filetype:yaml OR filetype:json \"aws_\""
            },
            {
                "Categoria": "Backups Esquecidos",
                "Objetivo": "Localizar cópias de segurança de bancos de dados ou códigos antigos expostos",
                "Query": f"site:{dominio_limpo} filetype:sql OR filetype:bak OR filetype:tar.gz"
            },
            {
                "Categoria": "Painéis Administrativos Expostos",
                "Objetivo": "Validar se telas de login internas/DevOps foram indexadas publicamente",
                "Query": f"site:{dominio_limpo} intitle:\"Dashboard [Jenkins]\" OR intitle:\"Grafana\" OR inurl:admin"
            },
            {
                "Categoria": "Documentos Internos e Planilhas",
                "Objetivo": "Mapear se planilhas financeiras ou PDFs confidenciais estão acessíveis",
                "Query": f"site:{dominio_limpo} filetype:xls OR filetype:xlsx OR filetype:pdf \"confidential\""
            }
        ]
        
        # Converte em DataFrame e adiciona os links clicáveis gerados de forma segura
        dados_auditoria = []
        for item in matriz_dorks:
            link_direto = f"https://google.com{quote_plus(item['Query'])}"
            dados_auditoria.append({
                "Categoria": item["Categoria"],
                "Objetivo": item["Objetivo"],
                "Dork de Teste": item["Query"],
                "Link para Verificação Manual": link_direto
            })
            
        df_auditoria = pd.DataFrame(dados_auditoria)
        
        st.subheader(f"📋 Plano de Teste de Exposição Externa: {dominio_limpo}")
        st.dataframe(df_auditoria, use_container_width=True, hide_index=True)
        
        st.info(
            "💡 **Como prosseguir:** Clique nos links gerados para rodar a pesquisa no Google. "
            "Se o Google retornar 'Nenhum resultado encontrado', significa que seu domínio está limpo para aquela categoria. "
            "Se houver resultados, os links exibidos mostram arquivos expostos que precisam ser removidos imediatamente do servidor."
        )
