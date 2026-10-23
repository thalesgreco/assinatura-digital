# Assinaturas Digitais estilo Bitcoin (ECDSA secp256k1)

Sistema em Python, com menu no terminal, para **aprender** como funcionam as assinaturas
digitais usadas no Bitcoin: frase mnemônica → chaves → assinatura → verificação.

> ⚠️ **Projeto educacional.** Não use para proteger valores reais. Veja a seção [Segurança](#segurança).

## Versões

| Arquivo | Para quê | Requisitos |
|---|---|---|
| `assinaturas.py` | **Educativa.** Curva elíptica, ECDSA e frases implementados à mão, sem dependências. Ideal para ler e entender o código. | Python 3.8+ |
| `assinaturas_lib.py` | **Com bibliotecas.** Mais curta e simples. Usa a lista BIP-39 oficial em português. | Python 3.11+, `ecdsa`, `mnemonic` |

As duas têm o mesmo menu, o mesmo formato de `.bin` e geram pacotes de assinatura equivalentes.

## Instalação

```bash
# Versão educativa: nada a instalar
python3 assinaturas.py

# Versão com bibliotecas
pip install ecdsa mnemonic
python3 assinaturas_lib.py
```

**Sem computador:** no iPhone, use o [Google Colab](https://colab.research.google.com).
Rode `!pip install ecdsa mnemonic`, grave o código com `%%writefile assinaturas_lib.py` e execute:

```python
import assinaturas_lib
assinaturas_lib.main()
```

Os arquivos do Colab são temporários: baixe as pastas `identidades/` e `pacotes/` se quiser guardá-las.

## Uso

O programa cria duas pastas no diretório onde for executado: `identidades/` e `pacotes/`.

| Opção | O que faz |
|---|---|
| **1. Nova identidade** | Gera 3 frases mnemônicas em português para você escolher, pede um nome e uma passphrase (opcional) e salva um `.bin`. |
| **2. Minhas identidades** | Lista as identidades e mostra frase, chave privada e chave pública da escolhida. |
| **3. Assinar texto** | Assina um texto e salva o pacote público em `pacotes/`. |
| **4. Assinar documento** | Igual à 3, mas para qualquer arquivo (o hash é do conteúdo do arquivo). |
| **5. Verificar assinatura** | Confere a autoria: conteúdo + assinatura + chave pública. |
| **6. Verificar integridade** | Confere só se o conteúdo bate com um hash (não prova quem assinou). |
| **7. Recuperar identidade** | Recria a identidade a partir da frase (e da passphrase, se houver). |

### Passphrase opcional (a "25ª palavra")

- Mesma frase + passphrase diferente = **outra identidade** (chaves totalmente diferentes).
- A passphrase **nunca é salva**: é pedida ao usar a identidade. Se esquecer, as chaves estão perdidas.
- Uma passphrase errada ao **usar** é detectada ("passphrase incorreta"). Ao **recuperar**, gera
  outra identidade silenciosamente, então confira a chave pública mostrada.
- Prefira uma passphrase longa. Passphrases fracas podem ser adivinhadas por quem tiver o `.bin`.

## Como funciona

```
frase mnemônica (+ passphrase) ──PBKDF2──▶ chave privada ──(× ponto G)──▶ chave pública
conteúdo ──SHA-256──▶ hash ──ECDSA(chave privada)──▶ assinatura (r, s)
verificação: ECDSA(hash, assinatura, chave pública) → válida / inválida
```

- **Curva:** secp256k1 (`y² = x³ + 7`), a mesma do Bitcoin. Parâmetros públicos definidos no padrão SEC 2.
- **Hash:** SHA-256 **simples** (texto em UTF-8; arquivos byte a byte), verificável em qualquer plataforma.
  O Bitcoin usa SHA-256 duplo; aqui foi escolhido o simples para facilitar a conferência externa.
- **O que é assinado:** o hash de 32 bytes, não o conteúdo.
- **Assinatura:** 64 bytes `r‖s` em hexadecimal, big-endian, com regra *low-S* do Bitcoin.
- **Chave pública:** 33 bytes comprimidos (SEC1), prefixo `02` ou `03`, em hexadecimal.
- **Nonce:** determinístico (versão com bibliotecas: RFC 6979; educativa: HMAC da chave e do hash).
  Nunca se repete para mensagens diferentes, o que evita o vazamento da chave privada.

## Arquivos gerados

### `identidades/<início da chave pública>.bin` (privado!)

Formato: `b"ASG2"` + `nome\nfrase\nchave_pública` em UTF-8. Sem criptografia.
Contém a frase mnemônica: **nunca compartilhe**.

### `pacotes/<início do hash>.json` (público)

Tudo o que alguém precisa para verificar a assinatura. **Seguro para publicar**: não contém frase nem chave privada.

```json
{
  "especificacao": {
    "algoritmo": "ECDSA, curva secp256k1",
    "hash": "SHA-256 simples (texto em UTF-8; arquivo byte a byte)",
    "o_que_e_assinado": "o hash de 32 bytes, não o conteúdo",
    "assinatura": "64 bytes r||s, big-endian, hexadecimal, low-S",
    "chave_publica": "33 bytes comprimidos (SEC1), hexadecimal"
  },
  "tipo": "texto",
  "conteudo": "Olá, mundo!",
  "hash_sha256": "9583b013baa520d3a893c4270d0c67732d7ef1768eb0a13533b4e7b134d4b131",
  "assinatura": "a7c7b36189e67fbdf0693bc6e405bdc99e11b729bf79db83285641649516e033016d781340be5934d50894355580c12f5eb898f7b1a94f365b4bc9e913b3a6f9",
  "chave_publica": "02e90c3035e72e7da92b9ae4cf98459e565da2ba91a2d3b23c7ee4b4f04f9cfbca"
}
```

Para documentos, o pacote traz `"tipo": "arquivo"` e `"nome_arquivo"` (sem o conteúdo).
Quem verifica precisa do arquivo original.

## Verificar sem o seu sistema

Qualquer pessoa pode verificar com **qualquer linguagem** que tenha ECDSA secp256k1:
basta seguir a `especificacao` do pacote. Exemplo em Python com a biblioteca `cryptography`
(`pip install cryptography`), salvo como `verificar_pacote.py`:

```python
import hashlib, json, sys
from pathlib import Path
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature

pacote = json.load(open(sys.argv[1], encoding="utf-8"))
if pacote["tipo"] == "texto":
    dados = pacote["conteudo"].encode("utf-8")
else:  # arquivo: passe o caminho do arquivo original como 2º argumento
    dados = Path(sys.argv[2]).read_bytes()

digest = hashlib.sha256(dados).digest()
if digest.hex() != pacote["hash_sha256"]:
    sys.exit("✘ O conteúdo não corresponde ao hash do pacote")

chave = ec.EllipticCurvePublicKey.from_encoded_point(
    ec.SECP256K1(), bytes.fromhex(pacote["chave_publica"]))
sig = pacote["assinatura"]
try:
    chave.verify(encode_dss_signature(int(sig[:64], 16), int(sig[64:], 16)),
                 digest, ec.ECDSA(Prehashed(hashes.SHA256())))
    print("✔ Assinatura VÁLIDA")
except Exception:
    sys.exit("✘ Assinatura INVÁLIDA")
```

```bash
python3 verificar_pacote.py pacotes/9583b013baa5.json                 # texto
python3 verificar_pacote.py pacotes/<hash>.json meu_documento.pdf      # arquivo
```

Também é possível conferir o hash por fora: `sha256sum arquivo` (Linux/macOS) ou
`certutil -hashfile arquivo SHA256` (Windows). Em JavaScript, a biblioteca `@noble/secp256k1` aceita
a assinatura `r‖s` diretamente.

## Estrutura do código

`assinaturas.py` (educativa), em seções comentadas:
1. **Curva elíptica:** parâmetros, soma de pontos, multiplicação, compressão de chave.
2. **Frase mnemônica:** lista de 256 palavras, geração e derivação da chave.
3. **Armazenamento:** leitura e escrita dos `.bin`, passphrase.
4. **Hash, assinatura e verificação:** SHA-256, ECDSA.
5. **Interface (CLI):** menu e fluxos.

`assinaturas_lib.py` mantém a mesma ordem, trocando as seções 1, 2 e 4 por chamadas às bibliotecas.

## Compatibilidade entre as versões

- **Assinaturas e chaves públicas:** qualquer uma pode verificar as assinaturas da outra (mesmo formato).
- **Frases mnemônicas:** a versão educativa usa uma lista própria de 256 palavras (16 por frase); a versão com
  bibliotecas usa a lista BIP-39 oficial (12 palavras). Uma frase criada em uma **não** serve na outra.
  Recupere cada identidade na versão em que foi criada.
- **Arquivos `.bin`:** mesmo formato (`ASG2`). Versões antigas (`ASG1`) são ignoradas: recrie pela opção 7.

## Segurança

- **O `.bin` não é criptografado.** Quem o tiver tem a frase e, sem passphrase, as chaves. Guarde-o como uma senha.
- **Nunca publique** frase, chave privada ou `.bin`. Publique apenas o pacote `.json` e a chave pública.
- **Derivação simplificada:** não usa BIP-32/44, então as chaves **não** coincidem com as de carteiras Bitcoin.
- A biblioteca `ecdsa` é Python puro, boa para estudo, mas sem proteção contra ataques de tempo.
  Para uso real, prefira `coincurve` (libsecp256k1) e uma carteira consolidada.

## Limitações conhecidas

- Interface somente em terminal; os dados ficam em arquivos locais da pasta de execução.
- A verificação de assinaturas (opção 5) pede os campos manualmente; ela ainda não lê o `.json` do pacote.
