def add(x, y):
    return x ^ y


# def multiply(x, y):
#     z = 0
#
#     for _ in range(8):
#         z ^= x & -(y & 1)
#         y >>= 1
#         x <<= 1
#         x ^= (0x11B & -(x >> 8))
#
#     return z

def multiply(p_1, p_2):  # Russian Peasant Algorithm from https://en.wikipedia.org/wiki/Finite_field_arithmetic#Program_examples
    product = 0x0
    while p_1 and p_2:
        if p_2 & 0x1:
            product = product ^ p_1
        if p_1 & 0x80:
            p_1 = (p_1 << 1) ^ 0x11B
        else:
            p_1 = p_1 << 1
        p_2 = p_2 >> 1
    return product


def invert(x):
    z = x
    for _ in range(6):
        z = multiply(z, z)
        z = multiply(z, x)

    return multiply(z, z)
