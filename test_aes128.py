import hashlib
import encrypt
import decrypt

from pprint import pprint


def blockify_and_matrix_msg(tokenized_msg):
    blockified_msg = []
    for i in range(len(tokenized_msg) // 16):
        blockified_msg.append([])
        for j in range(4):
            start_index = 4 * (4 * i + j)
            end_index = 4 * (4 * i + j + 1)
            blockified_msg[i].append(tokenized_msg[start_index:end_index])
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
    msg_list = [
            "6B", "C1", "BE", "E2", "2E", "40", "9F", "96", "E9", "3D", "7E", "11", "73", "93", "17", "2A", "AE", "2D",
            "8A", "57", "1E", "03", "AC", "9C", "9E", "B7", "6F", "AC", "45", "AF", "8E", "51", "30", "C8", "1C", "46",
            "A3", "5C", "E4", "11", "E5", "FB", "C1", "19", "1A", "0A", "52", "EF", "F6", "9F", "24", "45", "DF", "4F",
            "9B", "17", "AD", "2B", "41", "7B", "E6", "6C", "37", "10"
    ]

    blockified_msg = blockify_and_matrix_msg(hexify(msg_list))

    key_list = [
            "2B", "7E", "15", "16", "28", "AE", "D2", "A6", "AB", "F7", "15", "88", "09", "CF", "4F", "3C"
    ]

    blockified_key = blockify_and_matrix_msg(hexify(key_list))[0]

    pprint(blockified_msg)
    pprint(blockified_key)

    encrypt.encrypt(blockified_msg, blockified_key)


if __name__ == "__main__":
    main()
