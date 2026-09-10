"""
BPD Week 2: build a signed P2SH-P2WSH 2-of-2 multisig transaction.

This is offline: no bitcoind. We serialize a segwit tx, BIP143-sign it with
both keys, and write the hex to out.txt.
"""

import hashlib
from pathlib import Path

from ecdsa import SECP256k1, SigningKey
from ecdsa.util import sigencode_der_canonize

# --- assignment constants ----------------------------------------------------
PRIVKEY_1 = bytes.fromhex("39dc0a9f0b185a2ee56349691f34716e6e0cda06a7f9707742ac113c4e2317bf")
PRIVKEY_2 = bytes.fromhex("5077ccd9c558b7d04a81920d38aa11b4a9f9de3b23fab45c3ef28039920fdd6d")

# Witness script (the 2-of-2): OP_2 <pub1> <pub2> OP_2 OP_CHECKMULTISIG
WITNESS_SCRIPT = bytes.fromhex(
    "5221032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b"
    "21039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd5652ae"
)
PUB1 = bytes.fromhex("032ff8c5df0bc00fe1ac2319c3b8070d6d1e04cfbf4fedda499ae7b775185ad53b")
PUB2 = bytes.fromhex("039bbc8d24f89e5bc44c5b0d1980d6658316a6b2440023117c3c03a4975b04dd56")

PREVOUT_HASH = bytes.fromhex("00" * 32)
PREVOUT_INDEX = 0
SEQUENCE = 0xFFFFFFFF
LOCKTIME = 0
OUTPUT_VALUE = 100_000  # 0.001 BTC in satoshis; also the dummy input amount
OUTPUT_ADDRESS = "325UUecEQuyrTd28Xs2hvAxdAjHM7XzqVF"
SIGHASH_ALL = 0x01

OUT_FILE = Path(__file__).resolve().parent.parent / "out.txt"

B58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hash256(data: bytes) -> bytes:
    return sha256(sha256(data))


def hash160(data: bytes) -> bytes:
    return hashlib.new("ripemd160", sha256(data)).digest()


def compact_size(n: int) -> bytes:
    if n < 0xFD:
        return n.to_bytes(1, "little")
    if n <= 0xFFFF:
        return b"\xfd" + n.to_bytes(2, "little")
    if n <= 0xFFFFFFFF:
        return b"\xfe" + n.to_bytes(4, "little")
    return b"\xff" + n.to_bytes(8, "little")


def encode_push(data: bytes) -> bytes:
    """Script push of `data` (used for scriptSig)."""
    n = len(data)
    if n < 0x4C:
        return bytes([n]) + data
    if n <= 0xFF:
        return b"\x4c" + bytes([n]) + data
    raise ValueError("push too large")


def b58decode_check(address: str) -> bytes:
    n = 0
    for ch in address:
        n = n * 58 + B58.index(ch)
    raw = n.to_bytes((n.bit_length() + 7) // 8, "big")
    raw = b"\x00" * (len(address) - len(address.lstrip("1"))) + raw
    payload, checksum = raw[:-4], raw[-4:]
    if hash256(payload)[:4] != checksum:
        raise ValueError("bad base58 checksum")
    return payload


def p2sh_script_pubkey(address: str) -> bytes:
    payload = b58decode_check(address)
    version, h160 = payload[0], payload[1:]
    if version != 0x05 or len(h160) != 20:
        raise ValueError(f"not a mainnet P2SH address: {address}")
    # OP_HASH160 <20-byte-hash> OP_EQUAL
    return b"\xa9\x14" + h160 + b"\x87"


def compressed_pubkey(priv: bytes) -> bytes:
    vk = SigningKey.from_string(priv, curve=SECP256k1).get_verifying_key()
    return vk.to_string("compressed")


def sign_der(priv: bytes, digest: bytes) -> bytes:
    """Low-S DER signature of a 32-byte digest, plus SIGHASH_ALL."""
    sk = SigningKey.from_string(priv, curve=SECP256k1)
    der = sk.sign_digest(digest, sigencode=sigencode_der_canonize)
    return der + bytes([SIGHASH_ALL])


def bip143_sighash(
    version: int,
    prevout: bytes,
    sequence: int,
    script_code: bytes,
    amount: int,
    outputs: bytes,
    locktime: int,
) -> bytes:
    """BIP143 signature hash for a single-input P2WSH spend."""
    hash_prevouts = hash256(prevout)
    hash_sequence = hash256(sequence.to_bytes(4, "little"))
    hash_outputs = hash256(outputs)

    preimage = b"".join(
        [
            version.to_bytes(4, "little"),
            hash_prevouts,
            hash_sequence,
            prevout,
            script_code,
            amount.to_bytes(8, "little"),
            sequence.to_bytes(4, "little"),
            hash_outputs,
            locktime.to_bytes(4, "little"),
            SIGHASH_ALL.to_bytes(4, "little"),
        ]
    )
    return hash256(preimage)


def serialize_witness_stack(items: list[bytes]) -> bytes:
    parts = [compact_size(len(items))]
    for item in items:
        parts.append(compact_size(len(item)))
        parts.append(item)
    return b"".join(parts)


def main() -> None:
    version = 2

    # Nested redeem script that goes in scriptSig:
    #   OP_0 <sha256(witnessScript)>   ==  0020{32-byte-hash}
    # P2SH wraps that 22-byte program, which is what address 325UUe... encodes.
    nested_redeem = b"\x00\x20" + sha256(WITNESS_SCRIPT)
    script_sig = encode_push(nested_redeem)

    prevout = PREVOUT_HASH + PREVOUT_INDEX.to_bytes(4, "little")
    spk = p2sh_script_pubkey(OUTPUT_ADDRESS)
    serialized_output = OUTPUT_VALUE.to_bytes(8, "little") + compact_size(len(spk)) + spk

    # scriptCode for P2WSH is the witness script with its compact-size prefix.
    script_code = compact_size(len(WITNESS_SCRIPT)) + WITNESS_SCRIPT
    digest = bip143_sighash(
        version, prevout, SEQUENCE, script_code, OUTPUT_VALUE, serialized_output, LOCKTIME
    )

    # CHECKMULTISIG checks signatures in the same order as the pubkeys in the script.
    key_by_pub = {
        compressed_pubkey(PRIVKEY_1): PRIVKEY_1,
        compressed_pubkey(PRIVKEY_2): PRIVKEY_2,
    }
    sig1 = sign_der(key_by_pub[PUB1], digest)
    sig2 = sign_der(key_by_pub[PUB2], digest)

    # P2WSH 2-of-2 witness: dummy OP_0 (CHECKMULTISIG off-by-one), sigs, script.
    witness = serialize_witness_stack([b"", sig1, sig2, WITNESS_SCRIPT])

    # Segwit serialization: version | 00 | 01 | vin | vout | witnesses | locktime
    vin = b"".join(
        [
            compact_size(1),
            prevout,
            compact_size(len(script_sig)),
            script_sig,
            SEQUENCE.to_bytes(4, "little"),
        ]
    )
    vout = compact_size(1) + serialized_output

    raw = b"".join(
        [
            version.to_bytes(4, "little"),
            b"\x00\x01",
            vin,
            vout,
            witness,
            LOCKTIME.to_bytes(4, "little"),
        ]
    )

    OUT_FILE.write_text(raw.hex() + "\n", encoding="utf-8")
    print(f"Wrote {OUT_FILE}")
    print(raw.hex())


if __name__ == "__main__":
    main()
