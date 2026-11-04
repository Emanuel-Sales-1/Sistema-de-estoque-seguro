# Bancada de Drones

Sistema web para oficina de conserto de drones: **ordens de serviço** e **estoque de peças** no mesmo lugar, com login, perfis de acesso e registro de auditoria.

Junta duas ideias:

- a interface da *Bancada de Drones*: OS com cliente, telefone, orçamento, drone, defeito e status; catálogo de peças com custo, venda, margem, modelos compatíveis e site de compra; baixa e estorno de estoque por OS;
- a base segura do *Sistema de estoque*: Flask + SQLite, senhas com hash, perfis `admin`/`comum` e log que não pode ser alterado nem apagado.

## Funcionalidades

**Ordens de serviço**
- Lista com busca (cliente, telefone, nº do orçamento, drone, nº da OS) e filtro por status.
- Status: Aberta → Aguardando peças → Em reparo → Pronta p/ retirada → Entregue.
- Ficha com link de WhatsApp, peças da OS, quantidades, custo, venda e margem.
- Ao adicionar peças, as compatíveis com o drone da OS aparecem primeiro.
- **Dar baixa no estoque**: desconta todas as peças de uma vez, numa transação só, e só se houver estoque para todas. **Estornar baixa** devolve as peças ao estoque.

**Peças e estoque**
- Catálogo com tipo, custo, venda, margem, modelos compatíveis e site de compra.
- Ajuste rápido de estoque (+/−) e coluna de **reservado**: quanto as OS em aberto ainda vão consumir, com destaque quando falta.
- Resumo no topo: OS em andamento, aguardando peças, peças em falta e valor do estoque a custo.

**Segurança**
- Senhas com hash (Werkzeug); tempo de resposta igual para usuário que existe e que não existe.
- Proteção CSRF em todos os formulários `POST`.
- Cookies de sessão `HttpOnly`, `SameSite=Lax` e `Secure`; cabeçalhos CSP, `nosniff` e `Referrer-Policy`.
- SQL só com parâmetros; validação no servidor de todos os campos; URL de compra só com `http(s)`.
- Valores em centavos (inteiros), sem erro de arredondamento.
- Log de auditoria de logins, OS, peças, estoque e usuários, protegido por triggers contra `UPDATE`/`DELETE`.

| Ação | comum | admin |
|---|:-:|:-:|
| Criar e editar OS e peças, dar baixa, ajustar estoque | ✔ | ✔ |
| Excluir OS e peças | | ✔ |
| Gerenciar usuários e ver logs | | ✔ |

## Como rodar

```bash
python -m venv venv
source venv/bin/activate        # no Windows: venv\Scripts\activate
pip install -r requirements.txt

export SECRET_KEY="$(python -c 'import secrets; print(secrets.token_hex(32))')"
python criar_admin.py           # cria o primeiro administrador
```

Em produção (HTTPS):

```bash
gunicorn app:app
```

Para testar localmente sem HTTPS, desligue o cookie `Secure`:

```bash
COOKIE_SEGURO=0 flask --app app run
```

Variáveis de ambiente:

| Variável | Uso |
|---|---|
| `SECRET_KEY` | obrigatória; assina a sessão |
| `BANCADA_DB` | caminho do banco SQLite (padrão: `bancada.db` ao lado do código) |
| `COOKIE_SEGURO` | `0` para rodar sem HTTPS em desenvolvimento |
| `FLASK_DEBUG` | `1` para modo debug ao rodar `python app.py` |

## Estrutura

```
app.py           rotas, login, permissões, OS, peças, usuários e logs
db.py            esquema SQLite e funções de banco
validacao.py     validação dos formulários de OS e de peças
criar_admin.py   cria o primeiro administrador
templates/       páginas (Jinja2)
static/          estilo e um JS opcional (o sistema funciona sem ele)
```
