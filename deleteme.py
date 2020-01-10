def generate_key_schedule(key_):
    global key_schedule
    w = [[0 for x in range(4)] for y in range(44)]
    temp = [0 for x in range(4)]

    for row in range(len(key_)):
        for col in range(len(key_[row])):  # Transpose key_, put into first 4 cols of w
            w[row][col] = key_[col][row]

    for i in range(4, 44):
        if i % 4 != 0:
            w[i] = xor_col(w[i - 4], w[i - 1])
        else:
            w[i] = xor_col(w[i - 4], transform_col(w[i - 1], round_const(i // 4)))
    key_schedule = w

def gen_round_consts():
    rc = [None]*10
    for i in range(10):
        if i == 0:
            print("== 1")
            rc[i] = 1
        elif i > 0 and rc[i-1] < 0x80:
            print("1 < i < 0x80")
            rc[i] = 2*rc[i-1]
        elif i > 0 and rc[i - 1] >= 0x80:
            print("1 < i >= 0x80")
            rc[i] = ((2*rc[i-1]) ^ 0x1B) & 0xFF # Masking with 0xFF because elements in GF256 are 8 bits long
    return rc

gen_round_consts()
