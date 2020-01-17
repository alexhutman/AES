import hashlib
from encrypt import Encrypt
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

    key_list = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f" 
    ]

    #key_list = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f", "10", "11", "12", "13", "14", "15", "16", "17"] 

    #key_list = [
    #        "2B", "7E", "15", "16", "28", "AE", "D2", "A6", "AB", "F7", "15", "88", "09", "CF", "4F", "3C"
    #]

    blocked = tokenize(hexify_and_pad(msg_list), 16)
    blocked = vecs_to_matrices(blocked)
    #blocked = transpose_blocks(blocked)
    
    hexed_key = hexify(key_list)
    pprint(blocked)
    #pprint(blockified_key)
    #pprint(TEST_int_block_to_hex(blocked[0]))
    #pprint(key_list)

    print(f"FINAL RESULT: {Encrypt.AES128(blocked, hexed_key)}")
    #print(f"FINAL RESULT: {Encrypt.AES192(blocked, hexed_key)}")

if __name__ == "__main__":
    test()
