#!/usr/bin/env python3

import nfpython
from keys import load_key
from hashing import digest_message


def sign_message(conn, privkey: nfpython.KeyID, message: bytes) -> (nfpython.Hash32, nfpython.CipherText):
    """
    Hash and sign a binary string using the HSM and a loaded RSA private key
    :param conn:
    :param privkey: KeyID of loaded key
    :param message: bytes to sign
    :return: the digest hash and signature
    """
    digest = digest_message(conn, message)
    plain = nfpython.Hash32(digest)
    c = nfpython.Command()
    c.cmd = "Sign"
    c.args.mech = "RSAhSHA256pPKCS1"
    c.args.key = privkey
    c.args.plain.type = "Hash32"
    c.args.plain.data.data = plain

    rep = conn.transact(c)
    signature = rep.reply.sig
    return plain, signature


def verify_signature(conn, pubkey: nfpython.KeyID, digest, signature) -> bool:
    """
    Verify a signature using the HSM and a loaded public key
    :param conn:
    :param pubkey:
    :param digest:
    :param signature:
    :return:
    """
    digest[0] = 1
    cmd = nfpython.Command()
    cmd.cmd = "Verify"
    cmd.args.key = pubkey
    cmd.args.plain.type = "Hash32"
    cmd.args.plain.data.data = digest
    cmd.args.sig = signature

    conn.transact(cmd)


def run():
    conn = nfpython.connection(needworldinfo=True)
    privkey = load_key(conn, appname="simple", ident="signer")
    pubkey = load_key(conn, appname="simple", ident="signer", private=False)

    message_bytes = b"hello world" * 1024
    print(f"Hash and Sign {len(message_bytes)} bytes..")
    digest, signature = sign_message(conn, privkey, message_bytes)
    print("Verifying..")
    verify_signature(conn, pubkey, digest, signature)
    print("Done.")


if __name__ == "__main__":
    run()
