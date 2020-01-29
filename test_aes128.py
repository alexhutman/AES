import hashlib
from encrypt import AES128, AES192, AES256
import decrypt

from matrix import transpose, transpose_blocks
from pprint import pprint


def tokenize(iterable, n, fill=False):
    new_arr = []
    for i in range((len(iterable) + n - 1)//n):
        row = iterable[i*n:(i+1)*n]
        remaining = n-len(row)
        if remaining < 0:
            raise Exception("Tokenization is incorrect. \"remaining\" should be >= 0.\niterable: {}\tn: {}\tremaining: {}".format(iterable, n, remaining))
        if remaining > 0:
            row.extend(["00"]*remaining) 
        new_arr.append(row)
    return new_arr

def vecs_to_matrices(block):
    return [tokenize(vec, 4) for vec in block]

def blockify_and_matrix_msg(tokenized_msg):
    blockified_msg = []
    for block in range(len(tokenized_msg) // 16):
        blockified_msg.append([])
        for row_num in range(4):
            row = [tokenized_msg[4*row_num:4*col + row_num] for col in range(4)]
            blockified_msg[block].append(row)
    return blockified_msg

def hexify_and_pad(tokenized_arr):
    msg_length = len(tokenized_arr)
    pad_length = 0 if msg_length % 16 == 0 else ((msg_length // 16) + 1) * 16 - msg_length

    hex_arr = []
    for token in tokenized_arr:
        hex_arr.append(int(token, 16))
    for i in range(pad_length):
        hex_arr.append(0)
    return hex_arr

def hexify(tokenized_arr):
    return [int(token, 16) for token in tokenized_arr]

def TEST_int_block_to_hex(block):
    return [[hex(i) for i in row] for row in block]

def test():
    msg_list = ["00", "11", "22", "33", "44", "55", "66", "77", "88", "99", "aa", "bb", "cc", "dd", "ee", "ff" 
    ]
    #long_msg_list = ["00", "11", "22", "33", "44", "55", "66", "77", "88", "99", "aa", "bb", "cc", "dd", "ee", "ff",
    #   "33"]

    #key_list = [
    #        "2B", "7E", "15", "16", "28", "AE", "D2", "A6", "AB", "F7", "15", "88", "09", "CF", "4F", "3C"
    #]

    blocked = tokenize(hexify_and_pad(msg_list), 16)
    blocked = vecs_to_matrices(blocked)
    
    pprint(blocked)
    #pprint(blockified_key)
    #pprint(TEST_int_block_to_hex(blocked[0]))
    #pprint(key_list)
    
    true_ciphertexts = ["69c4e0d86a7b0430d8cdb78070b4c55a", "dda97ca4864cdfe06eaf70a0ec0d7191", "8ea2b7ca516745bfeafc49904b496089"]

    ciphertexts = []
    res_strings = []
    for i, cls in enumerate([AES128(), AES192(), AES256()]): 
        # 128, 192, and 256 bit test vectors from bottom of https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.197.pdf
        key_list = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f"]
        if i > 0:
            key_list += ["10", "11", "12", "13", "14", "15", "16", "17"] 
        if i > 1:
            key_list += ["18", "19", "1a", "1b", "1c", "1d", "1e", "1f"] 

        hexed_key = hexify(key_list)

        ciphertexts.append(cls.encrypt(blocked, hexed_key))

        if ciphertexts[i] != true_ciphertexts[i]:
            res_strings.append(f"{cls.__name__} FAILED: \"{ciphertexts[i]}\" != \"{true_ciphertexts[i]}\"")

    print("-"*25)

    if not res_strings:
        print("ALL TESTS HAVE PASSED!")
    else:
        for res_string in res_strings:
            print(res_string)


if __name__ == "__main__":
    test()
