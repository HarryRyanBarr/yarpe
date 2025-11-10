__all__ = ["p64", "p64a", "p32", "p32a", "p16", "p16a", "unpack"]


def p64(n):
    return [(a >> i) & 0xFF for a in n for i in range(0, 64, 8)]


def p64a(*n):
    return p64(n)


def p32(n):
    return [(a >> i) & 0xFF for a in n for i in range(0, 32, 8)]


def p32a(*n):
    return p32(n)


def p16(n):
    return [(a >> i) & 0xFF for a in n for i in range(0, 16, 8)]


def p16a(*n):
    return p16(n)


def unpack(buf):
    return sum(buf[i] << (i * 8) for i in range(len(buf)))
