import nfpython
import nfkm


def load_key(conn, appname: str, ident: str, module=0, private=True) -> nfpython.KeyID:
    """
    Load a key given an appname and ident
    :param conn:
    :param appname: Key appname, eg "simple"
    :param ident: Key ident
    :param module: module to load the key on (default 0 = any)
    :param private: load the private blob if true
    :return: the loaded key
    """
    appident = nfkm.KeyIdent(appname=appname, ident=ident)
    keydata = nfkm.findkey(conn, appident)

    cmd = nfpython.Command(cmd="LoadBlob")
    if private:
        cmd.args.blob = keydata.privblob
    else:
        cmd.args.blob = keydata.pubblob
    cmd.args.module = module

    rep = conn.transact(cmd)
    keyid = rep.reply.idka
    return keyid

