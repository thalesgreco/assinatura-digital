#!/usr/bin/env python3
"""
Assinaturas digitais estilo Bitcoin (ECDSA na curva secp256k1) - EDUCACIONAL.
Python puro, sem dependências. NÃO use para proteger valores reais.

Fluxo: frase mnemônica (+ passphrase opcional) -> chave privada -> chave pública.
Assinar: SHA-256 do conteúdo -> ECDSA(hash, chave privada) -> (r, s).
Pacote de assinatura = hash do conteúdo + assinatura + chave pública.
"""
import getpass
import hashlib
import hmac
import json
import secrets
import unicodedata
from pathlib import Path

# ============================ 1. CURVA ELÍPTICA ============================
# secp256k1: y² = x³ + 7 (mod P). G é o ponto gerador; N, a ordem do grupo.
P = 2**256 - 2**32 - 977
N = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
G = (0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
     0x483ADA7726A3C4655DA4FBFC0E1108A8FD17B448A68554199C47D08FFB10D4B8)


def inv(a, m):
    """Inverso modular: a * x ≡ 1 (mod m)."""
    return pow(a, -1, m)


def somar(a, b):
    """Soma dois pontos da curva (None = ponto no infinito)."""
    if a is None or b is None:
        return a or b
    (x1, y1), (x2, y2) = a, b
    if x1 == x2 and (y1 + y2) % P == 0:
        return None
    s = (3 * x1 * x1 * inv(2 * y1, P) if a == b else (y2 - y1) * inv(x2 - x1, P)) % P
    x3 = (s * s - x1 - x2) % P
    return x3, (s * (x1 - x3) - y1) % P


def multiplicar(k, ponto):
    """k * ponto pelo método double-and-add."""
    resultado = None
    while k:
        if k & 1:
            resultado = somar(resultado, ponto)
        ponto, k = somar(ponto, ponto), k >> 1
    return resultado


def pub_para_hex(pub):
    """Chave pública comprimida (formato Bitcoin): prefixo 02/03 + X."""
    return ("02" if pub[1] % 2 == 0 else "03") + f"{pub[0]:064x}"


def hex_para_pub(h):
    """Recupera o ponto (x, y) a partir da chave pública comprimida."""
    x = int(h[2:], 16)
    y = pow(x**3 + 7, (P + 1) // 4, P)  # raiz quadrada (P ≡ 3 mod 4)
    if y * y % P != (x**3 + 7) % P:
        raise ValueError("chave pública inválida")
    return (x, y) if y % 2 == int(h[:2], 16) - 2 else (x, P - y)


# ========================= 2. FRASE MNEMÔNICA (PT) =========================
# Lista própria de 256 palavras (8 bits cada). 16 palavras = 128 bits.
# Sem acentos, para evitar problemas de normalização Unicode.
PALAVRAS = """
abelha aldeia amigo areia arroz aurora azeite balao banana barco beijo bola brisa bruma
cabra cacau cadeira caderno caixa camelo caminho campo canela canoa carro casa castelo
cavalo cebola cereja chave chuva cidade cinza coelho cobre coral corda costa crianca dado
dente deserto diamante dragao duna escada escola espelho estrela fada farol feijao ferro
festa fio flauta floresta fogo folha fonte formiga fruta fumaca gaiola galinha gato gelo
girafa globo gota grama guitarra harpa horizonte ilha imagem inverno jacare janela jardim
jornal laranja leao lebre leite lenha livro lobo lua luz macaco madeira mala mapa mare
martelo mel melancia mesa metal milho mochila montanha morango muralha navio neve ninho
noite nuvem oceano olho onda ouro ovelha padaria pagina palavra panela papel passaro pedra
peixe pena pera perola piano pimenta pinheiro planeta plantio poeira ponte porta pote praia
prata prato primavera queijo rainha raio raiz ramo rato relogio remo rio roda rosa sabao
sal sapato selva semente serpente sino sol sombra sonho tambor tapete tartaruga teclado
telhado tempo terra tesouro tigre tinta tomate torre trem trigo trovao tulipa tunel uva
vaca vale varanda vela vento verao vidro vila vinho violao vulcao zebra abacaxi agulha
alface andorinha anel aranha armario bandeira baleia borboleta botao cachorro caneta carta
cenoura coruja cristal escudo espada falcao fazenda foguete fronteira garfo geleia jarra
joaninha lagoa lampada lanterna limao manga manteiga marfim moeda moinho nevoa orquidea
panda pato pirata pomar porco quadro rede relampago sereia tempestade tinteiro trilha
tucano urso vassoura velho vitoria xadrez zangao cometa bussola cacto canhao carvao cobra
colina coroa
""".split()


def gerar_frases(quantidade=3, tamanho=16):
    """Gera frases aleatórias (usa `secrets`, aleatoriedade criptográfica)."""
    return [" ".join(secrets.choice(PALAVRAS) for _ in range(tamanho))
            for _ in range(quantidade)]


def frase_para_chave_privada(frase, passphrase=""):
    """Frase (+ passphrase) -> seed (PBKDF2, como no BIP-39) -> chave privada em [1, N-1].
    A passphrase é a "25ª palavra": o salt do PBKDF2 é "mnemonic" + passphrase."""
    salt = unicodedata.normalize("NFKD", "mnemonic" + passphrase).encode()
    seed = hashlib.pbkdf2_hmac("sha512", frase.encode(), salt, 2048)
    return int.from_bytes(seed[:32], "big") % (N - 1) + 1


def pub_da_privada(priv):
    """Chave privada -> chave pública comprimida em hexadecimal."""
    return pub_para_hex(multiplicar(priv, G))


# ===================== 3. ARMAZENAMENTO (.bin POR IDENTIDADE) =====================
# Formato: b"ASG2" (identificador/versão) + "nome\nfrase\nchave_pública" em UTF-8.
# A passphrase NUNCA é salva: é pedida ao usar a identidade. A chave pública salva
# permite listar sem passphrase e detectar passphrase errada.
# ATENÇÃO: sem criptografia. Quem tiver o arquivo tem a frase (e, sem passphrase, a chave).
PASTA, MAGIC = Path("identidades"), b"ASG2"


def listar_identidades():
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
    priv = frase_para_chave_privada(i["frase"])
    if pub_da_privada(priv) != i["pub"]:
        priv = frase_para_chave_privada(i["frase"], getpass.getpass("Passphrase desta identidade: "))
        if pub_da_privada(priv) != i["pub"]:
            raise ValueError("passphrase incorreta")
    return priv


def salvar_identidade(nome, frase, passphrase=""):
    """Salva o .bin (um por identidade, nomeado pela chave pública) e devolve a pública."""
    pub = pub_da_privada(frase_para_chave_privada(frase, passphrase))
    PASTA.mkdir(exist_ok=True)
    (PASTA / f"{pub[2:10]}.bin").write_bytes(MAGIC + f"{nome}\n{frase}\n{pub}".encode())
    return pub


# ========================= 4. HASH, ASSINATURA E VERIFICAÇÃO =========================
def hash_texto(texto):
    """SHA-256 do texto em UTF-8 (reproduzível em qualquer plataforma)."""
    return hashlib.sha256(texto.encode("utf-8")).hexdigest()


def hash_arquivo(caminho):
    """SHA-256 dos bytes do arquivo, lido em blocos de 1 MB."""
    h = hashlib.sha256()
    with open(caminho, "rb") as f:
        for bloco in iter(lambda: f.read(1 << 20), b""):
            h.update(bloco)
    return h.hexdigest()


def assinar(priv, hash_hex):
    """ECDSA sobre o hash. Retorna r||s em hex (128 caracteres).
    O nonce k é derivado da chave + hash (HMAC): nunca se repete para
    mensagens diferentes, evitando o vazamento clássico da chave privada."""
    z = int(hash_hex, 16)
    k = int.from_bytes(hmac.new(priv.to_bytes(32, "big"), bytes.fromhex(hash_hex),
                                "sha256").digest(), "big") % (N - 1) + 1
    r = multiplicar(k, G)[0] % N
    s = inv(k, N) * (z + r * priv) % N
    return f"{r:064x}{min(s, N - s):064x}"  # "low-S", regra do Bitcoin


def verificar(pub_hex, hash_hex, assinatura):
    """Confere se a assinatura é válida para (hash, chave pública)."""
    try:
        r, s = int(assinatura[:64], 16), int(assinatura[64:], 16)
        pub, z = hex_para_pub(pub_hex), int(hash_hex, 16)
        if len(assinatura) != 128 or not (0 < r < N and 0 < s < N):
            return False
        w = inv(s, N)
        ponto = somar(multiplicar(z * w % N, G), multiplicar(r * w % N, pub))
        return ponto is not None and ponto[0] % N == r
    except ValueError:
        return False


# ================================ 5. INTERFACE (CLI) ================================
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
    frase = escolher(gerar_frases(), lambda f: f)
    pub = salvar_identidade(nome, frase, pedir_passphrase(confirmar=True))
    print(f"\nIdentidade criada! Chave pública: {pub}")


def recuperar_identidade():
    """Recria o .bin a partir da frase (e da passphrase, se houver). O nome não faz
    parte da frase; passphrase errada gera outra identidade (confira a chave pública)."""
    nome = input("Nome da identidade: ").strip()
    frase = " ".join(input("Frase mnemônica: ").lower().split())  # normaliza espaços/maiúsculas
    palavras = frase.split()
    if len(palavras) != 16 or not all(p in PALAVRAS for p in palavras):
        raise ValueError("frase inválida (confira as 16 palavras)")
    pub = salvar_identidade(nome, frase, pedir_passphrase())
    print(f"\nIdentidade recuperada! Chave pública: {pub}")


def minhas_identidades():
    i = escolher(listar_identidades(), lambda i: f"{i['nome']} ({i['pub'][:12]}...)")
    priv = abrir_chave(i)
    print(f"\nFrase mnemônica: {i['frase']}")
    print(f"Chave privada:   {priv:064x}")
    print(f"Chave pública:   {i['pub']}")


def assinar_conteudo(modo):
    i = escolher(listar_identidades(), lambda i: i["nome"])
    priv = abrir_chave(i)
    h, dados = pedir_conteudo(modo)
    assinatura = assinar(priv, h)
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
    assert len(set(PALAVRAS)) == 256, "a lista deve ter 256 palavras únicas"
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