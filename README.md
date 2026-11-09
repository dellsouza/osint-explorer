# OSINT Explorer

Aplicativo Streamlit para organizar resultados de pesquisa em fontes públicas.

## Executar
pip install -r requirements.txt
streamlit run app.py

## Publicar
Envie `app.py` e `requirements.txt` para um repositório GitHub e conecte o repositório ao Streamlit Community Cloud.

## Limites
- Resultados dependem do provedor de busca e podem falhar ou variar.
- A pontuação mede correspondência textual, não identidade.
- Não coleta dados privados nem tenta acessar contas.
- Esta versão mantém pesquisas apenas na sessão atual; não possui banco de dados persistente.
