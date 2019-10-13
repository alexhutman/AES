# TODO: Possibly add the option to do Cipher Block Chaining (CBC) mode?


import re
import Encrypt
import Decrypt

xCrypt = None
message = None
key = None


def preliminaries():
    global xCrypt
    global message
    global key

    xCryptPrompt = input("Would you like to: \n[1] encrypt a message \nOR \n[2] decrypt a message?\n")

    if xCryptPrompt == "1":
        xCrypt = "en"
        message = input("Input the message to encrypt: ")
        encKey = input("Input the 128 bit key you'd like to use to encrypt the message: ")
        keyMatch = re.match(r"^[A-Fa-f0-9]{32}$", encKey)
        if not keyMatch == None:
            key = encKey.upper()
        else:
            print("Invalid key")

    elif xCryptPrompt == "2":
        xCrypt = "de"
        message = input("Input the message to decrypt: ")  # MAYBE HAVE TO
        decKey = input("Input the 128 bit key you'd like to use to encrypt the message: ")
        keyMatch = re.match(r"^[A-Fa-f0-9]{32}$", decKey)
        if not keyMatch == None:
            key = decKey.upper()
        else:
            print("Invalid key")

    else:
        print("Please enter 1 or 2 to encrypt or decrypt a message, respectively.\n")
        preliminaries()


def padMessage(string_):
    msgLength = len(string_)
    padLength = 0 if msgLength % 16 == 0 else ((msgLength // 16) + 1) * 16
    return '{stringToPad:{fill}<{width}}'.format(stringToPad=string_, fill='0', width=padLength)


def blockifyMessage(string_):
    return [string_[i:i + 16] for i in range(0, len(string_), 16)]


def tokenize(string_, n):
    return [string_[i:i + n] for i in range(0, len(string_), n)]


def hexifyAndMatrixMsg(msg_):
    msgRows, msgCols = 4, 4
    stringMatrix = [[[0 for x in range(msgCols)] for y in range(msgRows)] for z in range(len(msg_))]
    for i in range(len(msg_)):
        for j in range(len(msg_[i])):
            stringMatrix[i][j % msgRows][j // msgCols] = int(hex(ord(msg_[i][j])), 16)
    return stringMatrix


def hexifyAndMatrixKey(key_):
    keyRows, keyCols = 4, len(key_) // 4
    stringMatrix = [[0 for x in range(keyCols)] for y in range(keyRows)]
    for i in range(len(key_)):
        stringMatrix[i % keyRows][i // keyRows] = int(key_[i], 16)
    return stringMatrix


# preliminaries()


# if xCrypt == "en":
# message = padMessage(message)
# message = blockifyMessage(message)
# for i in range(len(message)):                 UNCOMMENT AFTER FINISHED TESTING!
#    message[i] = tokenize(message[i],1)
# message = hexifyAndMatrixMsg(message)
# key = tokenize(key,1)
# key = hexifyAndMatrixKey(key)

def main():
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

    for i, block in enumerate(message[0]):
        for j, byte in enumerate(block):
            message[0][i][j] = int(byte, 16)

    for i, block in enumerate(key):
        for j, byte in enumerate(block):
            key[i][j] = int(byte, 16)

    Encrypt.encrypt(message, key)


if __name__ == "__main__":
    main()
