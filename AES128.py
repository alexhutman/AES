# TODO: Possibly add the option to do Cipher Block Chaining (CBC) mode?
import hashlib
import Encrypt
import Decrypt


def prompt_user():
    choice = input("Would you like to:\n[1] encrypt\nOR\n[2] decrypt a message?\nEnter here: ")
    while choice not in ["1", "2"]:
        input("Please choose\n[1] to encrypt a message\nOR\n[2] to decrypt a message.\nEnter here: ")

    if choice == "1":
        choice = "encrypt"
        message = pad_message(input("Input the message to encrypt: ").encode("utf-8").hex())

        # I am aware this is probably not secure or what happens in practice. Choosing the key is not in the
        # specification, so I thought to make the key this because it was the first thing that came to mind and was
        # easy to implement.
        key = input("Input the key you'd like to use to encrypt the message: ").encode("utf-8")
        key = hashlib.sha256(key).hexdigest()[:16]

        return choice, message, key

    elif choice == "2":
        print("Decrypt not implemented yet :(")
        exit(1)


def pad_message(string):
    msg_length = len(string)
    pad_length = 0 if msg_length % 16 == 0 else ((msg_length // 16) + 1) * 16
    return '{stringToPad:{fill}<{width}}'.format(stringToPad=string, fill='0', width=pad_length)


def blockify_message(string):
    return [string[i:i + 16] for i in range(0, len(string), 16)]


def tokenize(string, n):
    return [string[i:i + n] for i in range(0, len(string), n)]


def hexify_and_matrix_msg(msg):
    msg_rows, msg_cols = 4, 4
    string_matrix = [[[0 for x in range(msg_cols)] for y in range(msg_rows)] for z in range(len(msg))]
    for i in range(len(msg)):
        for j in range(len(msg[i])):
            string_matrix[i][j % msg_rows][j // msg_cols] = int(hex(ord(msg[i][j])), 16)
    return string_matrix


def hexify_and_matrix_key(key):
    key_rows, key_cols = 4, len(key) // 4
    string_matrix = [[0 for x in range(key_cols)] for y in range(key_rows)]
    for i in range(len(key)):
        string_matrix[i % key_rows][i // key_rows] = int(key[i], 16)
    return string_matrix


# preliminaries()


# if xCrypt == "en":
# message = pad_message(message)
# message = blockify_message(message)
# for i in range(len(message)):                 UNCOMMENT AFTER FINISHED TESTING!
#    message[i] = tokenize(message[i],1)
# message = hexify_and_matrix_msg(message)
# key = tokenize(key,1)
# key = hexify_and_matrix_key(key)

def main():
    """
    message = [
        [
            ["3F", "EE", "C0", "E3"], ["93", "29", "87", "A8"],
            ["F7", "78", "65", "87"], ["D4", "AE", "0B", "EF"]
        ]
    ]
    key = [
        ["42", "69", "54", "21"], ["F5", "79", "C9", "FE"],
        ["8D", "65", "52", "41"], ["96", "9F", "75", "05"]
    ]
    """
    choice, message, key = prompt_user()

    # TODO: I think I need to fix the padding. Doesn't seem right.
    # TODO: bytes.fromhex(message) converts back to msg

    tokenized = tokenize(message, 4)
    blockified = blockify_message(message)
    #message = hexify_and_matrix_msg(message)
    print(message)
    print(tokenized)
    print(blockified)
    exit(0)

    for i, block in enumerate(message[0]):
        for j, byte in enumerate(block):
            message[0][i][j] = int(byte, 16)

    for i, block in enumerate(key):
        for j, byte in enumerate(block):
            key[i][j] = int(byte, 16)

    Encrypt.encrypt(message, key)


if __name__ == "__main__":
    main()
