"""
Minimal CBOR implementation supporting a subset of functionality and types
required for FIDO 2 CTAP.
"""
from io import BytesIO

depth = 0


def dump_int(fout, data, mt=0):
    if data < 0:
        mt = 1
        data = -1 - data

    mt = mt << 5
    if data <= 23:
        return fout.write((mt | data).to_bytes(1, 'big'))
    elif data <= 0xFF:
        fout.write(bytes((mt | 24,)))
        return 1 + fout.write(data.to_bytes(1, 'big'))
    elif data <= 0xFFFF:
        fout.write(bytes((mt | 25,)))
        return 1 + fout.write(data.to_bytes(2, 'big'))
    elif data <= 0xFFFFFFFF:
        fout.write(bytes((mt | 26,)))
        return 1 + fout.write(data.to_bytes(4, 'big'))
    elif data <= 0xFFFFFFFFFFFFFFFF:
        fout.write(bytes((mt | 27,)))
        return 1 + fout.write(data.to_bytes(8, 'big'))
    raise ValueError


def dump_bool(fout, data):
    return fout.write(b"\xf5") if data else fout.write(b"\xf4")


def dump_list(fout, data):
    n = dump_int(fout, len(data), 4)
    for x in data:
        n += encode(x, fout)
    return n


def dump_dict(fout, data):
    n = dump_int(fout, len(data), mt=5)
    keys = []
    for k in data:
        _fout = BytesIO()
        encode(k, _fout)
        keys.append((_fout.getvalue(), k))
    for key_encoded, key in sorted(keys, key=lambda x: x[0]):
        n += fout.write(key_encoded)
        n += encode(data[key], fout)
    return n


def dump_bytes(fout, data):
    return dump_int(fout, len(data), 2) + fout.write(data)


def dump_text(fout, data):
    data_bytes = data.encode("utf8")
    return dump_int(fout, len(data_bytes), 3) + fout.write(data_bytes)


_SERIALIZERS = [
    (bool, dump_bool),
    (int, dump_int),
    (dict, dump_dict),
    (list, dump_list),
    (str, dump_text),
    (bytes, dump_bytes),
]


def encode(data, _fout=None):
    if _fout is None:
        fout = BytesIO()
    else:
        fout = _fout
    for k, v in _SERIALIZERS:
        if isinstance(data, k):
            if _fout is None:
                v(fout, data)
                return fout.getvalue()
            return v(fout, data)
    raise ValueError


def load_int(ai, fin):
    if ai < 24:
        return ai
    elif ai == 24:
        b = fin.read(1)
        if len(b) < 1:
            raise ValueError
        return b[0]
    elif ai == 25:
        b = fin.read(2)
        if len(b) < 2:
            raise ValueError
        return int.from_bytes(b, 'big')
    elif ai == 26:
        b = fin.read(4)
        if len(b) < 4:
            raise ValueError
        return int.from_bytes(b, 'big')
    elif ai == 27:
        b = fin.read(8)
        if len(b) < 8:
            raise ValueError
        return int.from_bytes(b, 'big')
    raise ValueError


def load_nint(ai, fin):
    val = load_int(ai, fin)
    return -1 - val


def load_bool(ai, fin):
    return ai == 21


def load_bytes(ai, fin):
    n = load_int(ai, fin)
    return fin.read(n)


def load_text(ai, fin):
    enc = load_bytes(ai, fin)
    return enc.decode("utf8")


def load_array(ai, fin):
    global depth
    depth += 1
    if depth > 4:
        raise ValueError
    n = load_int(ai, fin)
    values = []
    for i in range(n):
        val = decode_from(fin)
        values.append(val)
    depth -= 1
    return values


def load_map(ai, fin):
    global depth
    depth += 1
    if depth > 4:
        raise ValueError
    n = load_int(ai, fin)
    values = {}
    for i in range(n):
        k = decode_from(fin)
        v = decode_from(fin)
        values[k] = v
    depth -= 1
    return values


_DESERIALIZERS = {
    0: load_int,
    1: load_nint,
    2: load_bytes,
    3: load_text,
    4: load_array,
    5: load_map,
    7: load_bool,
}


def decode_from(fin):
    fb = fin.read(1)
    if fb == b'':
        raise ValueError
    return _DESERIALIZERS[fb[0] >> 5](fb[0] & 0b11111, fin)


def decode(fin):
    global depth
    depth = 0
    if isinstance(fin, bytes):
        fin = BytesIO(fin)
    value = decode_from(fin)
    if fin.read(1) != b'':
        raise ValueError
    return value
