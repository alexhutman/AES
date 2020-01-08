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
            rc[i] = (2*rc[i-1]) ^ 0x18
        print([hex(val) for val in rc if val])

gen_round_consts()
