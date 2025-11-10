from constants import nogc

__all__ = [
    "sizeof",
    "flat",
    "addrof",
    "to_hex",
    "alloc",
    "bytes",
]


# Thanks @chilaxan
def sizeof(obj):
    return type(obj).__sizeof__(obj)


def flat(*args):
    return [x for a in args for x in a]


def addrof(obj):
    return id(obj)


def to_hex(data):
    return str(data).encode("hex")


def alloc(size):
    ba = bytearray(size)
    nogc.append(ba)
    return ba


def bytes(arr):
    if type(arr) is int:
        return "\0" * arr

    return str(bytearray(arr))
