"""Cria o primeiro administrador. Rode uma vez: python criar_admin.py"""
import getpass
import sqlite3
import sys

import db


def main():
    db.criar_tabelas()

    if db.existe_admin():
        sys.exit("Já existe um administrador. Novos usuários são criados pela tela de usuários.")

    usuario = input("Usuário do administrador: ").strip().lower()
    senha = getpass.getpass("Senha (mínimo 8 caracteres): ")
    confirmacao = getpass.getpass("Repita a senha: ")

    if senha != confirmacao:
        sys.exit("As senhas não conferem.")

    erro = db.validar_credenciais(usuario, senha)
    if erro:
        sys.exit(erro)

    try:
        db.criar_usuario(usuario, senha, "admin")
    except sqlite3.IntegrityError:
        sys.exit("Esse nome de usuário já existe.")

    db.registrar("usuario_criado", f"{usuario} (admin) via criar_admin.py")
    print(f"Administrador '{usuario}' criado.")


if __name__ == "__main__":
    main()
