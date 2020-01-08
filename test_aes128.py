import hashlib
import encrypt
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

def hexify(tokenized_arr):
    msg_length = len(tokenized_arr)
    pad_length = 0 if msg_length % 16 == 0 else ((msg_length // 16) + 1) * 16 - msg_length

    hex_arr = []
    for token in tokenized_arr:
        hex_arr.append(int(token, 16))
    for i in range(pad_length):
        hex_arr.append(0)
    return hex_arr

def main():
    """
    Test vectors from:
    https://csrc.nist.gov/CSRC/media/Projects/Cryptographic-Standards-and-Guidelines/documents/examples/AES_Core128.pdf
    """
    #msg_list = [
    #        "6B", "C1", "BE", "E2", "2E", "40", "9F", "96", "E9", "3D", "7E", "11", "73", "93", "17", "2A", "AE", "2D",
    #        "8A", "57", "1E", "03", "AC", "9C", "9E", "B7", "6F", "AC", "45", "AF", "8E", "51", "30", "C8", "1C", "46",
    #        "A3", "5C", "E4", "11", "E5", "FB", "C1", "19", "1A", "0A", "52", "EF", "F6", "9F", "24", "45", "DF", "4F",
    #        "9B", "17", "AD", "2B", "41", "7B", "E6", "6C", "37", "10"
    #]

    msg_list = ["00", "11", "22", "33", "44", "55", "66", "77", "88", "99", "aa", "bb", "cc", "dd", "ee", "ff" 
    ]

    blockified_msg = blockify_and_matrix_msg(hexify(msg_list))
    #blockified_msg = blockify_and_matrix_msg(msg_list)
    pprint(blockified_msg)

    #key_list = [
    #        "2B", "7E", "15", "16", "28", "AE", "D2", "A6", "AB", "F7", "15", "88", "09", "CF", "4F", "3C"
    #]

    key_list = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f" 
    ]

    blockified_key = blockify_and_matrix_msg(hexify(key_list))[0]
    pprint(blockified_key)

    message = [
        ["3F", "EE", "C0", "E3"], ["93", "29", "87", "A8"],
        ["F7", "78", "65", "87"], ["D4", "AE", "0B", "EF"]
    ]
    
    #encrypt.encrypt(blockified_msg, blockified_key)

def test():
    msg_list = ["00", "11", "22", "33", "44", "55", "66", "77", "88", "99", "aa", "bb", "cc", "dd", "ee", "ff" 
    ]
    #long_msg_list = ["00", "11", "22", "33", "44", "55", "66", "77", "88", "99", "aa", "bb", "cc", "dd", "ee", "ff",
    #   "33"]
    key_list = ["00", "01", "02", "03", "04", "05", "06", "07", "08", "09", "0a", "0b", "0c", "0d", "0e", "0f" 
    ]

    blockified_key = tokenize(hexify(key_list), 4)

    blocked = tokenize(hexify(msg_list), 16)
    blocked = vecs_to_matrices(blocked)
    #blocked = transpose_blocks(blocked)

    pprint(blocked)
    pprint(blockified_key)

    encrypt.encrypt(blocked, blockified_key)

if __name__ == "__main__":
    #main()
    test()
