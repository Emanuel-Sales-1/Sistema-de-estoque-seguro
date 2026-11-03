import re
from decimal import Decimal, InvalidOperation
from urllib.parse import urlparse

from db import STATUS_LABEL

VALOR_MAX = Decimal("1000000")
ESTOQUE_RE = re.compile(r"[0-9]{1,7}")
TELEFONE_RE = re.compile(r"[0-9()+\-. ]{8,20}")


def _texto(form, campo, minimo, maximo, rotulo):
    valor = " ".join(form.get(campo, "").split())
    if not minimo <= len(valor) <= maximo:
        if minimo == 0:
            return None, f"{rotulo} deve ter no máximo {maximo} caracteres."
        return None, f"{rotulo} deve ter de {minimo} a {maximo} caracteres."
    if not valor.isprintable():
        return None, f"{rotulo} contém caracteres inválidos."
    return valor, None


def _centavos(form, campo, rotulo):
    texto = form.get(campo, "").strip().replace(",", ".")
    try:
        valor = Decimal(texto)
    except InvalidOperation:
        return None, f"Informe {rotulo} válido, por exemplo 12.50."
    if not valor.is_finite() or valor < 0 or valor > VALOR_MAX:
        return None, f"{rotulo.capitalize()} deve estar entre 0 e 1.000.000."
    if valor.as_tuple().exponent < -2:
        return None, f"{rotulo.capitalize()} deve ter no máximo 2 casas decimais."
    return int(valor * 100), None


def url_segura(texto):
    texto = (texto or "").strip()
    if not texto:
        return ""
    try:
        partes = urlparse(texto)
    except ValueError:
        return None
    if partes.scheme not in ("http", "https") or not partes.netloc:
        return None
    return texto


def validar_peca(form):
    nome, erro = _texto(form, "nome", 2, 100, "O nome")
    if erro:
        return None, erro
    tipo, erro = _texto(form, "tipo", 2, 50, "O tipo")
    if erro:
        return None, erro
    custo, erro = _centavos(form, "custo", "um custo")
    if erro:
        return None, erro
    venda, erro = _centavos(form, "venda", "um valor de venda")
    if erro:
        return None, erro

    texto_estoque = form.get("estoque", "0").strip() or "0"
    if not ESTOQUE_RE.fullmatch(texto_estoque):
        return None, "O estoque deve ser um número inteiro entre 0 e 9.999.999."

    modelos = []
    for m in form.get("modelos", "").split(","):
        m = " ".join(m.split())
        if not m:
            continue
        if len(m) > 60 or not m.isprintable():
            return None, "Cada modelo compatível deve ter no máximo 60 caracteres."
        if m.lower() not in (x.lower() for x in modelos):
            modelos.append(m)
    if len(modelos) > 30:
        return None, "Informe no máximo 30 modelos compatíveis."

    site = url_segura(form.get("site", ""))
    if site is None or len(site) > 500:
        return None, "O site precisa começar com http:// ou https:// e ter até 500 caracteres."

    return {
        "nome": nome, "tipo": tipo,
        "custo_centavos": custo, "venda_centavos": venda,
        "estoque": int(texto_estoque),
        "modelos": ", ".join(modelos), "site": site,
    }, None


def validar_ordem(form):
    cliente, erro = _texto(form, "cliente", 2, 100, "O nome do cliente")
    if erro:
        return None, erro
    telefone = form.get("telefone", "").strip()
    if not TELEFONE_RE.fullmatch(telefone):
        return None, "Informe um telefone válido, por exemplo (11) 98765-4321."
    orcamento, erro = _texto(form, "orcamento", 1, 30, "O nº do orçamento")
    if erro:
        return None, erro
    status = form.get("status", "aberta")
    if status not in STATUS_LABEL:
        return None, "Status inválido."
    drone, erro = _texto(form, "drone", 0, 80, "O drone")
    if erro:
        return None, erro
    defeito = form.get("defeito", "").strip()
    if len(defeito) > 1000:
        return None, "O defeito relatado deve ter no máximo 1000 caracteres."
    if not all(c.isprintable() or c in "\r\n\t" for c in defeito):
        return None, "O defeito relatado contém caracteres inválidos."

    return {
        "cliente": cliente, "telefone": telefone, "orcamento": orcamento,
        "status": status, "drone": drone, "defeito": defeito,
    }, None
