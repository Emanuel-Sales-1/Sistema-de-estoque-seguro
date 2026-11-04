import os
import re
import sqlite3

from werkzeug.security import generate_password_hash

DB = os.environ.get(
    "BANCADA_DB",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "bancada.db"),
)

PERFIS = ("admin", "comum")
USUARIO_RE = re.compile(r"^[a-z0-9._-]{3,50}$")

STATUS = (
    ("aberta", "Aberta"),
    ("aguardando", "Aguardando peças"),
    ("reparo", "Em reparo"),
    ("pronta", "Pronta p/ retirada"),
    ("entregue", "Entregue"),
)
STATUS_LABEL = dict(STATUS)


def conectar():
    con = sqlite3.connect(DB)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys = ON")
    return con


def criar_tabelas():
    with conectar() as con:
        con.executescript("""
            CREATE TABLE IF NOT EXISTS pecas (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                nome TEXT NOT NULL UNIQUE COLLATE NOCASE,
                tipo TEXT NOT NULL,
                custo_centavos INTEGER NOT NULL CHECK (custo_centavos >= 0),
                venda_centavos INTEGER NOT NULL CHECK (venda_centavos >= 0),
                estoque INTEGER NOT NULL DEFAULT 0 CHECK (estoque >= 0),
                modelos TEXT NOT NULL DEFAULT '',
                site TEXT NOT NULL DEFAULT '',
                criado_em TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
            );
            CREATE TABLE IF NOT EXISTS ordens (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                cliente TEXT NOT NULL,
                telefone TEXT NOT NULL,
                orcamento TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'aberta'
                    CHECK (status IN ('aberta','aguardando','reparo','pronta','entregue')),
                drone TEXT NOT NULL DEFAULT '',
                defeito TEXT NOT NULL DEFAULT '',
                baixado INTEGER NOT NULL DEFAULT 0,
                criado_em TEXT NOT NULL DEFAULT (datetime('now', 'localtime'))
            );
            CREATE TABLE IF NOT EXISTS ordem_itens (
                ordem_id INTEGER NOT NULL REFERENCES ordens(id) ON DELETE CASCADE,
                peca_id INTEGER NOT NULL REFERENCES pecas(id) ON DELETE RESTRICT,
                qtd INTEGER NOT NULL CHECK (qtd > 0),
                PRIMARY KEY (ordem_id, peca_id)
            );
            CREATE TABLE IF NOT EXISTS usuarios (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                usuario TEXT NOT NULL UNIQUE,
                senha_hash TEXT NOT NULL,
                perfil TEXT NOT NULL CHECK (perfil IN ('admin', 'comum')),
                ativo INTEGER NOT NULL DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                data TEXT NOT NULL DEFAULT (datetime('now', 'localtime')),
                usuario TEXT,
                acao TEXT NOT NULL,
                detalhe TEXT
            );
            CREATE TRIGGER IF NOT EXISTS logs_sem_update
            BEFORE UPDATE ON logs
            BEGIN
                SELECT RAISE(ABORT, 'os logs não podem ser alterados');
            END;
            CREATE TRIGGER IF NOT EXISTS logs_sem_delete
            BEFORE DELETE ON logs
            BEGIN
                SELECT RAISE(ABORT, 'os logs não podem ser apagados');
            END;
        """)


def validar_credenciais(usuario, senha):
    if not USUARIO_RE.match(usuario):
        return "Usuário deve ter de 3 a 50 caracteres: letras minúsculas, números, ponto, hífen ou sublinhado."
    if len(senha) < 8:
        return "A senha deve ter pelo menos 8 caracteres."
    if len(senha) > 128:
        return "A senha deve ter no máximo 128 caracteres."
    return None


def existe_admin():
    with conectar() as con:
        return con.execute(
            "SELECT 1 FROM usuarios WHERE perfil='admin' AND ativo=1 LIMIT 1"
        ).fetchone() is not None


def criar_usuario(usuario, senha, perfil):
    with conectar() as con:
        con.execute(
            "INSERT INTO usuarios (usuario, senha_hash, perfil) VALUES (?, ?, ?)",
            (usuario, generate_password_hash(senha), perfil),
        )


def registrar(acao, detalhe="", usuario=None):
    if usuario is not None:
        usuario = usuario[:50]
    with conectar() as con:
        con.execute(
            "INSERT INTO logs (usuario, acao, detalhe) VALUES (?, ?, ?)",
            (usuario, acao, detalhe[:200]),
        )


def reservado(con):
    linhas = con.execute("""
        SELECT i.peca_id, SUM(i.qtd) AS qtd
        FROM ordem_itens i JOIN ordens o ON o.id = i.ordem_id
        WHERE o.baixado = 0 AND o.status != 'entregue'
        GROUP BY i.peca_id
    """).fetchall()
    return {r["peca_id"]: r["qtd"] for r in linhas}
