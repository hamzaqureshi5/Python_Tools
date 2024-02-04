import nfpython


def digest_message(conn, message: bytes, module=0, mech="Sha256Hash", chunksize=8000) -> bytes:
    """
    Hash a binary string using the HSM and ChannelUpdate commands
    :param conn:
    :param message: binary message to hash.
    :param module: HSM to sign with (default 0 = any)
    :param mech: hash mechanism name
    :param chunksize: digest block size
    :return:
    """
    c = nfpython.Command()
    c.cmd = "ChannelOpen"
    c.args.type = "simple"
    c.args.mode = "sign"
    c.args.mech = mech
    c.args.module = module

    rep = conn.transact(c)
    channel = rep.reply.idch

    c = nfpython.Command()
    c.cmd = "ChannelUpdate"
    # split the message up into small chunks and transmit each in sequence
    for chunk in (message[i:i+chunksize] for i in range(0, len(message), chunksize)):
        c.args.idch = channel
        c.args.input = nfpython.ByteBlock(chunk, fromraw=True)
        conn.transact(c)

    # obtain the hash value by setting the final flag
    c.args.input = nfpython.ByteBlock()
    c.args.flags |= "final"
    rep = conn.transact(c)
    digest = rep.reply.output
    return digest
