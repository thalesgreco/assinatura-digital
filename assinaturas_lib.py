#!/usr/bin/env python3
"""
Assinaturas digitais estilo Bitcoin (ECDSA secp256k1) - versão com bibliotecas.
Mesmo menu e mesmo formato de .bin da versão educativa (assinaturas.py).

Instalação (requer Python 3.11+):  pip install ecdsa mnemonic
  - mnemonic: frases BIP-39 oficiais, inclusive a lista de 2048 palavras em português
  - ecdsa:    curva secp256k1, chaves e ECDSA com nonce determinístico (RFC 6979)

Fluxo: frase (+ passphrase opcional) -> chave privada -> chave pública.
Pacote de assinatura = hash SHA-256 do conteúdo + assinatura + chave pública.
"""
import getpass
import hashlib
import json
from pathlib import Path

from ecdsa import SECP256k1, SigningKey, VerifyingKey
from ecdsa.util import sigdecode_string, sigencode_string_canonize
from mnemonic import Mnemonic

BIP39 = Mnemonic("portuguese")
# Um .bin por identidade: b"ASG2" + "nome\nfrase\nchave_pública". Sem criptografia: é educativo!
# A passphrase NUNCA é salva: é pedida ao usar. A pública salva permite listar sem
# passphrase e detectar passphrase errada.
PASTA, MAGIC = Path("identidades"), b"ASG2"


# ========================= 1. CHAVES E ARMAZENAMENTO =========================
def frase_para_chave(frase, passphrase=""):
    """Frase (+ passphrase, a "25ª palavra") -> seed BIP-39 (PBKDF2) -> chave privada."""
    segredo = int.from_bytes(BIP39.to_seed(frase, passphrase)[:32], "big") % (SECP256k1.order - 1) + 1
    return SigningKey.from_secret_exponent(segredo, SECP256k1)


def pub_hex(chave):
    """Chave pública comprimida (33 bytes, formato Bitcoin) em hexadecimal."""
    return chave.verifying_key.to_string("compressed").hex()


def carregar_identidades():
    """Lê os .bin (ignora arquivos de versões antigas). Não deriva chaves."""
    identidades = []
    for caminho in sorted(PASTA.glob("*.bin")):
        dados = caminho.read_bytes()
        if dados.startswith(MAGIC):
            nome, frase, pub = dados[len(MAGIC):].decode().split("\n")
            identidades.append({"nome": nome, "frase": frase, "pub": pub})
    if not identidades:
        raise ValueError("nenhuma identidade criada ainda")
    return identidades


def pedir_passphrase(confirmar=False):
    """Lê a passphrase sem mostrá-la na tela. Vazia = sem passphrase."""
    p = getpass.getpass("Passphrase (opcional; se esquecer, perde as chaves): ")
    if confirmar and p and p != getpass.getpass("Repita a passphrase: "):
        raise ValueError("as passphrases não conferem")
    return p


def abrir_chave(i):
    """Devolve a chave privada da identidade. Tenta sem passphrase; se a chave
    pública não bater, pede a passphrase e confere de novo."""
    chave = frase_para_chave(i["frase"])
    if pub_hex(chave) != i["pub"]:
        chave = frase_para_chave(i["frase"], getpass.getpass("Passphrase desta identidade: "))
        if pub_hex(chave) != i["pub"]:
            raise ValueError("passphrase incorreta")
    return chave


def salvar_identidade(nome, frase, passphrase=""):
    """Grava o .bin (nomeado pelo início da chave pública) e devolve a pública."""
    pub = pub_hex(frase_para_chave(frase, passphrase))
    PASTA.mkdir(exist_ok=True)
    (PASTA / f"{pub[2:10]}.bin").write_bytes(MAGIC + f"{nome}\n{frase}\n{pub}".encode())
    return pub


# ================== 2. HASH, ASSINATURA E VERIFICAÇÃO ==================
def hash_texto(texto):
    """SHA-256 do texto em UTF-8 (reproduzível em qualquer plataforma)."""
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def hash_arquivo(caminho):
    """SHA-256 dos bytes do arquivo (lido em blocos, sem estourar a memória)."""
    with open(caminho, "rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def assinar(chave, hash_hex):
    """ECDSA sobre o hash, com nonce RFC 6979 e 'low-S' (regra do Bitcoin).
    Retorna r||s em hexadecimal (128 caracteres)."""
    return chave.sign_digest_deterministic(
        bytes.fromhex(hash_hex), hashfunc=hashlib.sha256,
        sigencode=sigencode_string_canonize).hex()


def verificar(pub, hash_hex, assinatura):
    """True se a assinatura for válida para (hash, chave pública)."""
    try:
        chave = VerifyingKey.from_string(bytes.fromhex(pub), curve=SECP256k1)
        return chave.verify_digest(bytes.fromhex(assinatura),
                                   bytes.fromhex(hash_hex), sigdecode=sigdecode_string)
    except Exception:  # entrada malformada ou assinatura errada = inválida
        return False


# ============================ 3. INTERFACE (CLI) ============================
def escolher(itens, rotulo):
    """Mostra uma lista numerada e devolve o item escolhido."""
    for i, item in enumerate(itens, 1):
        print(f"  [{i}] {rotulo(item)}")
    n = int(input("> "))
    if not 1 <= n <= len(itens):
        raise ValueError("opção inválida")
    return itens[n - 1]


def pedir_conteudo(modo):
    """Pede um texto (modo '1') ou um arquivo (modo '2').
    Retorna (hash SHA-256, dados descritivos para o pacote público)."""
    if modo == "1":
        texto = input("Texto: ")
        return hash_texto(texto), {"tipo": "texto", "conteudo": texto}
    caminho = input("Caminho do arquivo: ").strip().strip('"')
    return hash_arquivo(caminho), {"tipo": "arquivo", "nome_arquivo": Path(caminho).name}


# Pacote público: tudo o que qualquer pessoa precisa para verificar a assinatura.
# NUNCA inclua frase mnemônica ou chave privada nele.
PASTA_PACOTES = Path("pacotes")
ESPECIFICACAO = {
    "algoritmo": "ECDSA, curva secp256k1",
    "hash": "SHA-256 simples (texto em UTF-8; arquivo byte a byte)",
    "o_que_e_assinado": "o hash de 32 bytes, não o conteúdo",
    "assinatura": "64 bytes r||s, big-endian, hexadecimal, low-S",
    "chave_publica": "33 bytes comprimidos (SEC1), hexadecimal",
}


def salvar_pacote(dados, hash_hex, assinatura, pub):
    """Grava pacotes/<início do hash>.json e devolve o caminho."""
    PASTA_PACOTES.mkdir(exist_ok=True)
    caminho = PASTA_PACOTES / f"{hash_hex[:12]}.json"
    pacote = {"especificacao": ESPECIFICACAO, **dados, "hash_sha256": hash_hex,
              "assinatura": assinatura, "chave_publica": pub}
    caminho.write_text(json.dumps(pacote, indent=2, ensure_ascii=False), encoding="utf-8")
    return caminho


def escolher_modo():
    return input("Conteúdo: [1] Texto  [2] Arquivo > ").strip()


def nova_identidade():
    nome = input("Nome da identidade: ").strip()
    frase = escolher([BIP39.generate(128) for _ in range(3)], lambda f: f)
    pub = salvar_identidade(nome, frase, pedir_passphrase(confirmar=True))
    print(f"\nIdentidade criada! Chave pública: {pub}")


def recuperar_identidade():
    """Recria o .bin a partir da frase (e da passphrase, se houver). O nome não faz
    parte da frase; passphrase errada gera outra identidade (confira a chave pública)."""
    nome = input("Nome da identidade: ").strip()
    frase = " ".join(input("Frase mnemônica: ").lower().split())  # normaliza espaços/maiúsculas
    if not BIP39.check(frase):  # confere palavras (com acentos) e checksum
        raise ValueError("frase inválida (palavra errada, faltando ou fora de ordem)")
    pub = salvar_identidade(nome, frase, pedir_passphrase())
    print(f"\nIdentidade recuperada! Chave pública: {pub}")


def minhas_identidades():
    i = escolher(carregar_identidades(), lambda i: f"{i['nome']} ({i['pub'][:12]}...)")
    chave = abrir_chave(i)
    print(f"\nFrase mnemônica: {i['frase']}")
    print(f"Chave privada:   {chave.to_string().hex()}")
    print(f"Chave pública:   {i['pub']}")


def assinar_conteudo(modo):
    i = escolher(carregar_identidades(), lambda i: i["nome"])
    chave = abrir_chave(i)
    h, dados = pedir_conteudo(modo)
    assinatura = assinar(chave, h)
    caminho = salvar_pacote(dados, h, assinatura, i["pub"])
    print(f"\nHash SHA-256: {h}\nAssinatura:   {assinatura}\n"
          f"Chave pública: {i['pub']}\n\nPacote público salvo em: {caminho}")


def verificar_assinatura():
    h, _ = pedir_conteudo(escolher_modo())
    ok = verificar(input("Chave pública: ").strip(), h, input("Assinatura: ").strip())
    print("\n✔ Assinatura VÁLIDA" if ok else "\n✘ Assinatura INVÁLIDA")


def verificar_integridade():
    calculado, _ = pedir_conteudo(escolher_modo())
    ok = calculado == input("Hash informado: ").strip().lower()
    print("\n✔ Conteúdo ÍNTEGRO (hash confere)" if ok else
          f"\n✘ Hash diferente! Calculado: {calculado}")


MENU = {
    "1": ("Nova identidade", nova_identidade),
    "2": ("Minhas identidades", minhas_identidades),
    "3": ("Assinar texto", lambda: assinar_conteudo("1")),
    "4": ("Assinar documento", lambda: assinar_conteudo("2")),
    "5": ("Verificar assinatura", verificar_assinatura),
    "6": ("Verificar integridade (conteúdo + hash)", verificar_integridade),
    "7": ("Recuperar identidade (frase mnemônica)", recuperar_identidade),
}


def main():
    try:
        while True:
            print("\n=== ASSINATURAS DIGITAIS (ECDSA secp256k1) ===")
            for tecla, (titulo, _) in MENU.items():
                print(f"[{tecla}] {titulo}")
            op = input("[0] Sair\n> ").strip()
            if op == "0":
                break
            if op in MENU:
                try:
                    MENU[op][1]()
                except (OSError, ValueError) as erro:
                    print(f"Erro: {erro}")
    except (EOFError, KeyboardInterrupt):
        pass


if __name__ == "__main__":
    main()