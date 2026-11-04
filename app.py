import os
import re
import secrets
import sqlite3
import unicodedata
from functools import wraps

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, session, url_for)
from markupsafe import Markup
from werkzeug.security import check_password_hash, generate_password_hash

import db
from db import PERFIS, STATUS, STATUS_LABEL, conectar
from validacao import validar_ordem, validar_peca

app = Flask(__name__)

chave = os.environ.get("SECRET_KEY")
if not chave:
    raise RuntimeError(
        'Defina a variável de ambiente SECRET_KEY. Exemplo para gerar uma: '
        'python -c "import secrets; print(secrets.token_hex(32))"'
    )

app.config.update(
    SECRET_KEY=chave,
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SEGURO", "1") != "0",
    MAX_CONTENT_LENGTH=64 * 1024,
)

db.criar_tabelas()

HASH_FALSO = generate_password_hash("qualquer-coisa-aqui")


def quem():
    usuario = g.get("usuario")
    return usuario["usuario"] if usuario else None


def norm(texto):
    texto = unicodedata.normalize("NFD", str(texto or "").lower())
    return "".join(c for c in texto if not unicodedata.combining(c))


def lista_modelos(peca):
    return [m.strip() for m in (peca["modelos"] or "").split(",") if m.strip()]


def compativel(modelo, drone):
    d, m = norm(drone), norm(modelo)
    return bool(d and m and (m in d or d in m))


def peca_compativel(peca, drone):
    return any(compativel(m, drone) for m in lista_modelos(peca))


@app.template_filter("brl")
def brl(centavos):
    centavos = int(centavos or 0)
    sinal = "-" if centavos < 0 else ""
    reais, cent = divmod(abs(centavos), 100)
    return f"{sinal}R$ {reais:,}".replace(",", ".") + f",{cent:02d}"


@app.template_filter("dataBR")
def data_br(texto):
    texto = texto or ""
    return f"{texto[8:10]}/{texto[5:7]}/{texto[0:4]}" if len(texto) >= 10 else texto


@app.template_filter("numos")
def num_os(id):
    return f"OS {int(id):04d}"


@app.template_filter("host")
def host(url):
    m = re.match(r"https?://(?:www\.)?([^/:?#]+)", url or "")
    return m.group(1) if m else ""


def whatsapp(telefone):
    digitos = re.sub(r"\D", "", telefone or "")
    if len(digitos) < 10:
        return ""
    return "https://wa.me/" + ("55" + digitos if len(digitos) <= 11 else digitos)


def token_csrf():
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


@app.before_request
def verificar_csrf():
    if request.method == "POST":
        enviado = request.form.get("csrf", "")
        esperado = session.get("csrf", "")
        if not esperado or not secrets.compare_digest(enviado, esperado):
            db.registrar("csrf_invalido", f"{request.method} {request.path}", None)
            abort(400)


@app.before_request
def carregar_usuario():
    g.usuario = None
    uid = session.get("usuario_id")
    if uid is None:
        return
    with conectar() as con:
        u = con.execute(
            "SELECT id, usuario, perfil FROM usuarios WHERE id=? AND ativo=1", (uid,)
        ).fetchone()
    if u is None:
        session.clear()
    else:
        g.usuario = u


@app.after_request
def cabecalhos_seguranca(resposta):
    resposta.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' https://fonts.googleapis.com; "
        "font-src https://fonts.gstatic.com; img-src 'self' data:; "
        "script-src 'self'; frame-ancestors 'none'; form-action 'self'",
    )
    resposta.headers.setdefault("X-Content-Type-Options", "nosniff")
    resposta.headers.setdefault("Referrer-Policy", "same-origin")
    return resposta


@app.context_processor
def injetar_globais():
    return {
        "usuario": g.get("usuario"),
        "csrf_field": lambda: Markup(
            f'<input type="hidden" name="csrf" value="{token_csrf()}">'
        ),
        "STATUS": STATUS,
        "STATUS_LABEL": STATUS_LABEL,
    }


def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if g.usuario is None:
            return redirect(url_for("login"))
        return f(*args, **kwargs)
    return wrapper


def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if g.usuario is None:
            return redirect(url_for("login"))
        if g.usuario["perfil"] != "admin":
            abort(403)
        return f(*args, **kwargs)
    return wrapper


@app.errorhandler(403)
def acesso_negado(erro):
    db.registrar("acesso_negado", f"{request.method} {request.path}", quem())
    return render_template("acesso_negado.html"), 403


def pagina_erro(titulo, mensagem, codigo):
    return render_template("erro.html", titulo=titulo, mensagem=mensagem), codigo


@app.errorhandler(400)
def requisicao_invalida(erro):
    return pagina_erro("Requisição inválida",
                       "Os dados enviados não puderam ser entendidos. Recarregue a página e tente de novo.", 400)


@app.errorhandler(404)
def nao_encontrado(erro):
    return pagina_erro("Página não encontrada", "O endereço que você tentou abrir não existe.", 404)


@app.errorhandler(405)
def metodo_nao_permitido(erro):
    return pagina_erro("Ação não permitida", "Essa ação não pode ser feita por esse caminho.", 405)


@app.errorhandler(413)
def grande_demais(erro):
    return pagina_erro("Dados grandes demais", "O formulário enviado passou do tamanho permitido.", 413)


@app.errorhandler(500)
def erro_interno(erro):
    return pagina_erro("Algo deu errado", "Não foi possível concluir a operação. Tente novamente.", 500)


@app.route("/login", methods=["GET", "POST"])
def login():
    if g.usuario is not None:
        return redirect(url_for("index"))

    if request.method == "POST":
        nome = request.form.get("usuario", "").strip().lower()
        senha = request.form.get("senha", "")

        tamanho_ok = len(nome) <= 50 and len(senha) <= 128
        u = None
        confere = False
        if tamanho_ok:
            with conectar() as con:
                u = con.execute("SELECT * FROM usuarios WHERE usuario=?", (nome,)).fetchone()
            confere = check_password_hash(u["senha_hash"] if u else HASH_FALSO, senha)

        if u is not None and u["ativo"] and confere:
            session.clear()
            session["usuario_id"] = u["id"]
            db.registrar("login", "", u["usuario"])
            return redirect(url_for("index"))

        motivo = "conta desativada" if u is not None and not u["ativo"] else "usuário ou senha incorretos"
        db.registrar("login_falhou", motivo, nome)
        flash("Usuário ou senha inválidos.", "erro")
        return render_template("login.html"), 401

    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    if g.usuario is not None:
        db.registrar("logout", "", quem())
    session.clear()
    return redirect(url_for("login"))


def resumo(con):
    abertas = con.execute("SELECT COUNT(*) FROM ordens WHERE status != 'entregue'").fetchone()[0]
    aguardando = con.execute("SELECT COUNT(*) FROM ordens WHERE status = 'aguardando'").fetchone()[0]
    res = db.reservado(con)
    pecas = con.execute("SELECT id, estoque, custo_centavos FROM pecas").fetchall()
    faltando = sum(1 for p in pecas if res.get(p["id"], 0) > p["estoque"])
    valor = sum(p["custo_centavos"] * p["estoque"] for p in pecas)
    return {"abertas": abertas, "aguardando": aguardando, "faltando": faltando, "valor": valor}


@app.route("/")
@login_required
def index():
    return redirect(url_for("ordens"))


def carregar_ordem(con, id):
    ordem = con.execute("SELECT * FROM ordens WHERE id=?", (id,)).fetchone()
    if ordem is None:
        abort(404)
    return ordem


def itens_da_ordem(con, ordem):
    linhas = con.execute("""
        SELECT i.qtd, p.* FROM ordem_itens i JOIN pecas p ON p.id = i.peca_id
        WHERE i.ordem_id = ? ORDER BY p.tipo, p.nome
    """, (ordem["id"],)).fetchall()
    itens = []
    for p in linhas:
        itens.append({
            "peca": p,
            "qtd": p["qtd"],
            "modelos": [(m, compativel(m, ordem["drone"])) for m in lista_modelos(p)],
            "subtotal": p["venda_centavos"] * p["qtd"],
            "falta": max(0, p["qtd"] - p["estoque"]),
        })
    return itens


@app.route("/ordens")
@login_required
def ordens():
    q = request.args.get("q", "").strip()[:80]
    filtro_status = request.args.get("status", "")
    if filtro_status not in STATUS_LABEL:
        filtro_status = ""
    busca = request.args.get("busca", "").strip()[:80]

    with conectar() as con:
        todas = con.execute("SELECT * FROM ordens ORDER BY id DESC").fetchall()
        nq = norm(q)
        lista = [
            o for o in todas
            if (not filtro_status or o["status"] == filtro_status)
            and (not nq or any(nq in norm(v) for v in
                               (o["cliente"], o["telefone"], o["orcamento"], o["drone"], f"os{o['id']:04d}")))
        ]

        sel = None
        sel_id = request.args.get("id", type=int)
        if sel_id is not None:
            sel = con.execute("SELECT * FROM ordens WHERE id=?", (sel_id,)).fetchone()
        elif lista:
            sel = lista[0]

        ficha = None
        if sel is not None:
            itens = itens_da_ordem(con, sel)
            custo = sum(i["peca"]["custo_centavos"] * i["qtd"] for i in itens)
            venda = sum(i["subtotal"] for i in itens)
            no_os = {i["peca"]["id"]: i["qtd"] for i in itens}
            nb = norm(busca)
            catalogo = [
                {"peca": p, "compativel": peca_compativel(p, sel["drone"]), "na_os": no_os.get(p["id"], 0)}
                for p in con.execute("SELECT * FROM pecas").fetchall()
                if not nb or any(nb in norm(v) for v in (p["nome"], p["tipo"], p["modelos"]))
            ]
            catalogo.sort(key=lambda c: (not c["compativel"], norm(c["peca"]["nome"])))
            ficha = {
                "ordem": sel,
                "itens": itens,
                "custo": custo, "venda": venda, "lucro": venda - custo,
                "margem": round((venda - custo) * 100 / venda) if venda else None,
                "pode_baixar": not sel["baixado"] and itens and all(i["falta"] == 0 for i in itens),
                "whatsapp": whatsapp(sel["telefone"]),
                "catalogo": catalogo[:50],
            }

        dados_resumo = resumo(con)

    return render_template(
        "ordens.html", lista=lista, total=len(todas), ficha=ficha, resumo=dados_resumo,
        q=q, filtro_status=filtro_status, busca=busca,
    )


def ir_para(id, **extra):
    return redirect(url_for("ordens", id=id, **extra))


@app.route("/ordens/nova", methods=["GET", "POST"])
@login_required
def nova_ordem():
    if request.method == "POST":
        dados, erro = validar_ordem(request.form)
        if erro:
            flash(erro, "erro")
            return render_template("ordem_form.html", ordem=request.form), 400
        with conectar() as con:
            cur = con.execute(
                "INSERT INTO ordens (cliente, telefone, orcamento, status, drone, defeito) "
                "VALUES (:cliente, :telefone, :orcamento, :status, :drone, :defeito)", dados)
            id = cur.lastrowid
        db.registrar("os_criada", f"{num_os(id)} | {dados['cliente']} | orç. {dados['orcamento']}", quem())
        flash(f"{num_os(id)} aberta.", "ok")
        return ir_para(id)
    return render_template("ordem_form.html", ordem=None)


@app.route("/ordens/<int:id>/editar", methods=["GET", "POST"])
@login_required
def editar_ordem(id):
    with conectar() as con:
        ordem = carregar_ordem(con, id)
    if request.method == "POST":
        dados, erro = validar_ordem(request.form)
        if erro:
            flash(erro, "erro")
            return render_template("ordem_form.html", ordem={**request.form, "id": id}), 400
        with conectar() as con:
            con.execute(
                "UPDATE ordens SET cliente=:cliente, telefone=:telefone, orcamento=:orcamento, "
                "status=:status, drone=:drone, defeito=:defeito WHERE id=:id", {**dados, "id": id})
        mudancas = [f"{k}: {ordem[k]} -> {v}" for k, v in dados.items() if k != "defeito" and str(ordem[k]) != str(v)]
        if ordem["defeito"] != dados["defeito"]:
            mudancas.append("defeito alterado")
        db.registrar("os_editada", f"{num_os(id)} | " + ("; ".join(mudancas) or "sem mudanças"), quem())
        flash("Dados da OS atualizados.", "ok")
        return ir_para(id)
    return render_template("ordem_form.html", ordem=ordem)


@app.route("/ordens/<int:id>/status", methods=["POST"])
@login_required
def status_ordem(id):
    novo = request.form.get("status", "")
    if novo not in STATUS_LABEL:
        abort(400)
    with conectar() as con:
        ordem = carregar_ordem(con, id)
        con.execute("UPDATE ordens SET status=? WHERE id=?", (novo, id))
    if ordem["status"] != novo:
        db.registrar("os_status", f"{num_os(id)} | {ordem['status']} -> {novo}", quem())
        flash(f"Status: {STATUS_LABEL[novo]}.", "ok")
    return ir_para(id)


@app.route("/ordens/<int:id>/excluir", methods=["POST"])
@admin_required
def excluir_ordem(id):
    with conectar() as con:
        ordem = carregar_ordem(con, id)
        con.execute("DELETE FROM ordens WHERE id=?", (id,))
    db.registrar("os_excluida", f"{num_os(id)} | {ordem['cliente']} | orç. {ordem['orcamento']}", quem())
    flash(f"{num_os(id)} excluída.", "ok")
    return redirect(url_for("ordens"))


def ordem_editavel(con, id):
    ordem = carregar_ordem(con, id)
    if ordem["baixado"]:
        flash("As peças desta OS já foram baixadas. Estorne a baixa para alterar a lista.", "erro")
        return None
    return ordem


@app.route("/ordens/<int:id>/itens", methods=["POST"])
@login_required
def adicionar_item(id):
    peca_id = request.form.get("peca_id", type=int)
    with conectar() as con:
        if ordem_editavel(con, id) is None:
            return ir_para(id)
        peca = con.execute("SELECT nome FROM pecas WHERE id=?", (peca_id,)).fetchone()
        if peca is None:
            flash("Peça não encontrada.", "erro")
            return ir_para(id)
        con.execute("""
            INSERT INTO ordem_itens (ordem_id, peca_id, qtd) VALUES (?, ?, 1)
            ON CONFLICT (ordem_id, peca_id) DO UPDATE SET qtd = MIN(qtd + 1, 9999)
        """, (id, peca_id))
    db.registrar("os_peca_adicionada", f"{num_os(id)} | +1 {peca['nome']}", quem())
    return ir_para(id)


@app.route("/ordens/<int:id>/itens/<int:peca_id>/qtd", methods=["POST"])
@login_required
def alterar_item(id, peca_id):
    delta = request.form.get("delta", type=int)
    if delta not in (-1, 1):
        abort(400)
    with conectar() as con:
        if ordem_editavel(con, id) is None:
            return ir_para(id)
        item = con.execute(
            "SELECT i.qtd, p.nome FROM ordem_itens i JOIN pecas p ON p.id=i.peca_id "
            "WHERE i.ordem_id=? AND i.peca_id=?", (id, peca_id)).fetchone()
        if item is None:
            abort(404)
        nova = min(item["qtd"] + delta, 9999)
        if nova <= 0:
            con.execute("DELETE FROM ordem_itens WHERE ordem_id=? AND peca_id=?", (id, peca_id))
        else:
            con.execute("UPDATE ordem_itens SET qtd=? WHERE ordem_id=? AND peca_id=?", (nova, id, peca_id))
    db.registrar("os_peca_qtd", f"{num_os(id)} | {item['nome']}: {item['qtd']} -> {max(nova, 0)}", quem())
    return ir_para(id)


@app.route("/ordens/<int:id>/itens/<int:peca_id>/remover", methods=["POST"])
@login_required
def remover_item(id, peca_id):
    with conectar() as con:
        if ordem_editavel(con, id) is None:
            return ir_para(id)
        item = con.execute(
            "SELECT i.qtd, p.nome FROM ordem_itens i JOIN pecas p ON p.id=i.peca_id "
            "WHERE i.ordem_id=? AND i.peca_id=?", (id, peca_id)).fetchone()
        if item is None:
            abort(404)
        con.execute("DELETE FROM ordem_itens WHERE ordem_id=? AND peca_id=?", (id, peca_id))
    db.registrar("os_peca_removida", f"{num_os(id)} | {item['qtd']}x {item['nome']}", quem())
    return ir_para(id)


@app.route("/ordens/<int:id>/baixar", methods=["POST"])
@login_required
def baixar(id):
    con = conectar()
    try:
        con.execute("BEGIN IMMEDIATE")
        ordem = carregar_ordem(con, id)
        itens = con.execute("""
            SELECT i.qtd, p.id, p.nome, p.estoque FROM ordem_itens i JOIN pecas p ON p.id=i.peca_id
            WHERE i.ordem_id=?""", (id,)).fetchall()
        if ordem["baixado"]:
            erro = "As peças desta OS já foram baixadas."
        elif not itens:
            erro = "Adicione peças à OS antes de dar baixa."
        else:
            faltas = [f"{i['nome']} (faltam {i['qtd'] - i['estoque']})" for i in itens if i["estoque"] < i["qtd"]]
            erro = "Estoque insuficiente: " + ", ".join(faltas) if faltas else None
        if erro:
            con.rollback()
            flash(erro, "erro")
            return ir_para(id)
        for i in itens:
            con.execute("UPDATE pecas SET estoque = estoque - ? WHERE id=?", (i["qtd"], i["id"]))
        con.execute("UPDATE ordens SET baixado=1 WHERE id=?", (id,))
        con.commit()
    finally:
        con.close()
    db.registrar("os_baixa", f"{num_os(id)} | " + ", ".join(f"{i['qtd']}x {i['nome']}" for i in itens), quem())
    flash("Baixa feita: as peças foram descontadas do estoque.", "ok")
    return ir_para(id)


@app.route("/ordens/<int:id>/estornar", methods=["POST"])
@login_required
def estornar(id):
    con = conectar()
    try:
        con.execute("BEGIN IMMEDIATE")
        ordem = carregar_ordem(con, id)
        if not ordem["baixado"]:
            con.rollback()
            flash("Esta OS não tem baixa para estornar.", "erro")
            return ir_para(id)
        itens = con.execute("""
            SELECT i.qtd, p.id, p.nome FROM ordem_itens i JOIN pecas p ON p.id=i.peca_id
            WHERE i.ordem_id=?""", (id,)).fetchall()
        for i in itens:
            con.execute("UPDATE pecas SET estoque = MIN(estoque + ?, 9999999) WHERE id=?", (i["qtd"], i["id"]))
        con.execute("UPDATE ordens SET baixado=0 WHERE id=?", (id,))
        con.commit()
    finally:
        con.close()
    db.registrar("os_estorno", f"{num_os(id)} | " + ", ".join(f"{i['qtd']}x {i['nome']}" for i in itens), quem())
    flash("Baixa estornada: as peças voltaram ao estoque.", "ok")
    return ir_para(id)


@app.route("/pecas")
@login_required
def pecas():
    q = request.args.get("q", "").strip()[:80]
    filtro_tipo = request.args.get("tipo", "").strip()[:50]
    with conectar() as con:
        todas = con.execute("SELECT * FROM pecas ORDER BY tipo COLLATE NOCASE, nome COLLATE NOCASE").fetchall()
        res = db.reservado(con)
        dados_resumo = resumo(con)
    tipos = sorted({p["tipo"] for p in todas}, key=norm)
    nq = norm(q)
    linhas = []
    for p in todas:
        if filtro_tipo and p["tipo"] != filtro_tipo:
            continue
        if nq and not any(nq in norm(v) for v in (p["nome"], p["tipo"], p["modelos"])):
            continue
        venda = p["venda_centavos"]
        linhas.append({
            "peca": p,
            "modelos": lista_modelos(p),
            "margem": round((venda - p["custo_centavos"]) * 100 / venda) if venda else 0,
            "reservado": res.get(p["id"], 0),
        })
    return render_template(
        "pecas.html", linhas=linhas, total=len(todas), tipos=tipos, resumo=dados_resumo,
        q=q, filtro_tipo=filtro_tipo,
    )


def tipos_existentes():
    with conectar() as con:
        return [r[0] for r in con.execute("SELECT DISTINCT tipo FROM pecas ORDER BY tipo COLLATE NOCASE")]


def voltar_pecas():
    os_id = request.values.get("os", type=int)
    return ir_para(os_id) if os_id else redirect(url_for("pecas"))


@app.route("/pecas/nova", methods=["GET", "POST"])
@login_required
def nova_peca():
    os_id = request.values.get("os", type=int)
    if request.method == "POST":
        dados, erro = validar_peca(request.form)
        if erro:
            flash(erro, "erro")
            return render_template("peca_form.html", peca=request.form, tipos=tipos_existentes(), os_id=os_id), 400
        try:
            with conectar() as con:
                cur = con.execute(
                    "INSERT INTO pecas (nome, tipo, custo_centavos, venda_centavos, estoque, modelos, site) "
                    "VALUES (:nome, :tipo, :custo_centavos, :venda_centavos, :estoque, :modelos, :site)", dados)
                peca_id = cur.lastrowid
                adicionada = False
                if os_id:
                    ordem = con.execute("SELECT baixado FROM ordens WHERE id=?", (os_id,)).fetchone()
                    if ordem is not None and not ordem["baixado"]:
                        con.execute("INSERT INTO ordem_itens (ordem_id, peca_id, qtd) VALUES (?, ?, 1)", (os_id, peca_id))
                        adicionada = True
        except sqlite3.IntegrityError:
            flash("Já existe uma peça com esse nome.", "erro")
            return render_template("peca_form.html", peca=request.form, tipos=tipos_existentes(), os_id=os_id), 400
        db.registrar(
            "peca_criada",
            f"{dados['nome']} | {dados['tipo']} | custo {brl(dados['custo_centavos'])} | "
            f"venda {brl(dados['venda_centavos'])} | estoque {dados['estoque']}",
            quem(),
        )
        if adicionada:
            db.registrar("os_peca_adicionada", f"{num_os(os_id)} | +1 {dados['nome']}", quem())
        flash("Peça cadastrada" + (" e adicionada à OS." if adicionada else "."), "ok")
        return voltar_pecas()

    sugestao = None
    if os_id:
        with conectar() as con:
            o = con.execute("SELECT drone FROM ordens WHERE id=?", (os_id,)).fetchone()
        if o is not None and o["drone"]:
            sugestao = {"modelos": o["drone"]}
    return render_template("peca_form.html", peca=sugestao, tipos=tipos_existentes(), os_id=os_id, nova=True)


@app.route("/pecas/<int:id>/editar", methods=["GET", "POST"])
@login_required
def editar_peca(id):
    os_id = request.values.get("os", type=int)
    with conectar() as con:
        antiga = con.execute("SELECT * FROM pecas WHERE id=?", (id,)).fetchone()
        usos = con.execute("SELECT COUNT(*) FROM ordem_itens WHERE peca_id=?", (id,)).fetchone()[0]
    if antiga is None:
        abort(404)
    if request.method == "POST":
        dados, erro = validar_peca(request.form)
        if erro:
            flash(erro, "erro")
            return render_template("peca_form.html", peca={**request.form, "id": id}, tipos=tipos_existentes(),
                                   os_id=os_id, usos=usos), 400
        try:
            with conectar() as con:
                con.execute(
                    "UPDATE pecas SET nome=:nome, tipo=:tipo, custo_centavos=:custo_centavos, "
                    "venda_centavos=:venda_centavos, estoque=:estoque, modelos=:modelos, site=:site WHERE id=:id",
                    {**dados, "id": id})
        except sqlite3.IntegrityError:
            flash("Já existe outra peça com esse nome.", "erro")
            return render_template("peca_form.html", peca={**request.form, "id": id}, tipos=tipos_existentes(),
                                   os_id=os_id, usos=usos), 400
        mudancas = []
        for campo in ("nome", "tipo", "estoque", "modelos", "site"):
            if str(antiga[campo]) != str(dados[campo]):
                mudancas.append(f"{campo}: {antiga[campo]} -> {dados[campo]}")
        for campo in ("custo_centavos", "venda_centavos"):
            if antiga[campo] != dados[campo]:
                mudancas.append(f"{campo.split('_')[0]}: {brl(antiga[campo])} -> {brl(dados[campo])}")
        db.registrar("peca_editada", f"id {id} | " + ("; ".join(mudancas) or "sem mudanças"), quem())
        flash("Peça atualizada.", "ok")
        return voltar_pecas()
    peca = {**dict(antiga),
            "custo": f"{antiga['custo_centavos'] / 100:.2f}",
            "venda": f"{antiga['venda_centavos'] / 100:.2f}"}
    return render_template("peca_form.html", peca=peca, tipos=tipos_existentes(), os_id=os_id, usos=usos)


@app.route("/pecas/<int:id>/estoque", methods=["POST"])
@login_required
def ajustar_estoque(id):
    delta = request.form.get("delta", type=int)
    if delta not in (-1, 1):
        abort(400)
    with conectar() as con:
        p = con.execute("SELECT nome, estoque FROM pecas WHERE id=?", (id,)).fetchone()
        if p is None:
            abort(404)
        novo = min(max(0, p["estoque"] + delta), 9999999)
        con.execute("UPDATE pecas SET estoque=? WHERE id=?", (novo, id))
    if novo != p["estoque"]:
        db.registrar("estoque_ajustado", f"{p['nome']}: {p['estoque']} -> {novo}", quem())
    return redirect(url_for("pecas", q=request.form.get("q", ""), tipo=request.form.get("tipo", "")))


@app.route("/pecas/<int:id>/excluir", methods=["POST"])
@admin_required
def excluir_peca(id):
    with conectar() as con:
        p = con.execute("SELECT nome FROM pecas WHERE id=?", (id,)).fetchone()
        if p is None:
            abort(404)
        usos = con.execute("SELECT COUNT(*) FROM ordem_itens WHERE peca_id=?", (id,)).fetchone()[0]
        if usos:
            flash(f"Essa peça está em {usos} OS. Remova-a das ordens antes de excluir.", "erro")
            return redirect(url_for("editar_peca", id=id))
        con.execute("DELETE FROM pecas WHERE id=?", (id,))
    db.registrar("peca_excluida", f"id {id}: {p['nome']}", quem())
    flash("Peça excluída.", "ok")
    return redirect(url_for("pecas"))


@app.route("/usuarios")
@admin_required
def listar_usuarios():
    with conectar() as con:
        usuarios = con.execute(
            "SELECT id, usuario, perfil, ativo FROM usuarios ORDER BY usuario"
        ).fetchall()
    return render_template("usuarios.html", usuarios=usuarios)


@app.route("/usuarios/adicionar", methods=["POST"])
@admin_required
def adicionar_usuario():
    nome = request.form.get("usuario", "").strip().lower()
    senha = request.form.get("senha", "")
    perfil = request.form.get("perfil", "")

    erro = db.validar_credenciais(nome, senha)
    if perfil not in PERFIS:
        erro = "Perfil inválido."
    if erro:
        flash(erro, "erro")
        return redirect(url_for("listar_usuarios"))

    try:
        db.criar_usuario(nome, senha, perfil)
    except sqlite3.IntegrityError:
        flash("Esse nome de usuário já existe.", "erro")
        return redirect(url_for("listar_usuarios"))

    db.registrar("usuario_criado", f"{nome} ({perfil})", quem())
    flash(f"Usuário '{nome}' criado.", "ok")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuarios/<int:id>/perfil", methods=["POST"])
@admin_required
def alterar_perfil(id):
    perfil = request.form.get("perfil", "")
    with conectar() as con:
        alvo = con.execute("SELECT usuario, perfil FROM usuarios WHERE id=?", (id,)).fetchone()

    if alvo is None:
        flash("Usuário não encontrado.", "erro")
    elif perfil not in PERFIS:
        flash("Perfil inválido.", "erro")
    elif id == g.usuario["id"]:
        flash("Você não pode alterar o seu próprio perfil.", "erro")
    elif alvo["perfil"] == perfil:
        flash("O usuário já tem esse perfil.", "erro")
    else:
        with conectar() as con:
            con.execute("UPDATE usuarios SET perfil=? WHERE id=?", (perfil, id))
        db.registrar("perfil_alterado", f"{alvo['usuario']}: {alvo['perfil']} -> {perfil}", quem())
        flash("Perfil atualizado.", "ok")
    return redirect(url_for("listar_usuarios"))


@app.route("/usuarios/<int:id>/ativo", methods=["POST"])
@admin_required
def alternar_ativo(id):
    with conectar() as con:
        alvo = con.execute("SELECT usuario, ativo FROM usuarios WHERE id=?", (id,)).fetchone()

    if alvo is None:
        flash("Usuário não encontrado.", "erro")
    elif id == g.usuario["id"]:
        flash("Você não pode desativar a sua própria conta.", "erro")
    else:
        novo = 1 - alvo["ativo"]
        with conectar() as con:
            con.execute("UPDATE usuarios SET ativo=? WHERE id=?", (novo, id))
        acao = "usuario_reativado" if novo else "usuario_desativado"
        db.registrar(acao, alvo["usuario"], quem())
        flash("Conta reativada." if novo else "Conta desativada.", "ok")
    return redirect(url_for("listar_usuarios"))


@app.route("/logs")
@admin_required
def ver_logs():
    filtro_usuario = request.args.get("usuario", "").strip().lower()[:50]
    filtro_acao = request.args.get("acao", "").strip()[:50]

    consulta = "SELECT * FROM logs WHERE 1=1"
    parametros = []
    if filtro_usuario:
        consulta += " AND usuario = ?"
        parametros.append(filtro_usuario)
    if filtro_acao:
        consulta += " AND acao = ?"
        parametros.append(filtro_acao)
    consulta += " ORDER BY id DESC LIMIT 200"

    with conectar() as con:
        logs = con.execute(consulta, parametros).fetchall()
        acoes = [r["acao"] for r in con.execute("SELECT DISTINCT acao FROM logs ORDER BY acao")]

    return render_template(
        "logs.html", logs=logs, acoes=acoes,
        filtro_usuario=filtro_usuario, filtro_acao=filtro_acao,
    )


if __name__ == "__main__":
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")
