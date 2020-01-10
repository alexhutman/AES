class GF256:
    @staticmethod
    def add(x, y):
        return (x ^ y) & 0xff # Apply 0xff bitmask to ensure we only get the first 8 bits


    #@staticmethod
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

    @staticmethod
    def multiply(p1, p2):  # Russian Peasant Algorithm from https://en.wikipedia.org/wiki/Finite_field_arithmetic#Program_examples
        product = 0x0
        while p1 and p2:
            if p_2 & 0x1:
                product = product ^ p1
            if p1 & 0x80:
                p1 = (p1 << 1) ^ 0x11b
            else:
                p1 = p1 << 1
            p2 = p2 >> 1
        return product

    @staticmethod
    def invert(x):
        z = x
        for _ in range(6):
            z = GF256.multiply(z, z)
            z = GF256.multiply(z, x)

        return GF256.multiply(z, z)
