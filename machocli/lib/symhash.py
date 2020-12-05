from hashlib import md5

def symhash(binary):
    """
    Compute symhash
    Based on https://github.com/threatstream/symhash
    https://www.anomali.com/blog/symhash
    """
    sym_list = []
    for s in binary.imported_symbols:
        sym_list.append(s.name)
    return md5(','.join(sorted(sym_list)).encode()).hexdigest()
