# TODO: Possibly add the option to do Cipher Block Chaining (CBC) mode?
import hashlib
import encrypt
import decrypt


def prompt_user():
    choice = input("Would you like to:\n\t[1] encrypt a message\n\t[2] decrypt a message\nEnter here: ")
    while choice not in ["1", "2"]:
        choice = input("Please input either 1 or 2.\n\t[1] to encrypt a message\n\t[2] to decrypt a message.\nEnter "
                       "here: ")

    if choice == "1":
        choice = "encrypt"
        message = input("Input the message to encrypt: ")
        while not message:
            message = input("Please enter the message you'd like to encrypt: ")
        message = pad_message(message).encode("utf-8").hex()

        # I am aware this is probably not secure or what happens in practice. Choosing the key is not in the
        # specification, so I thought to make the key this because it was the first thing that came to mind and was
        # easy to implement.
        key = input("Input the key you'd like to use to encrypt the message with: ")
        while not key:
            key = input("Please enter the key you'd like to use to encrypt the message with: ")
        key = hashlib.sha256(key.encode("utf-8")).hexdigest()[:32]

        return choice, message, key

    elif choice == "2":
        print("Decrypt not implemented yet :(")
        exit(1)


def pad_message(string):
    msg_length = len(string)
    pad_length = 0 if msg_length % 32 == 0 else ((msg_length // 32) + 1) * 32
    return '{stringToPad:{fill}<{width}}'.format(stringToPad=string, fill='0', width=pad_length)


def tokenize(string, n):
    return [string[i:i + n] for i in range(0, len(string), n)]


def hexify(tokenized_arr):
    hex_arr = []
    for token in tokenized_arr:
        hex_arr.append(int(token, 16))
    return hex_arr


def blockify_and_matrix_msg(tokenized_msg):
    blockified_msg = []
    for i in range(len(tokenized_msg) // 16):
        blockified_msg.append([])
        for j in range(4):
            start_index = 4 * (4 * i + j)
            end_index = 4 * (4 * i + j + 1)
            blockified_msg[i].append(tokenized_msg[start_index:end_index])
    return blockified_msg


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

    # TODO: For decryption (whenever that time comes), bytes.fromhex(message).decode('utf-8') converts back to msg

    print(message)
    tokenized_msg = tokenize(message, 2)
    hexified_msg = hexify(tokenized_msg)
    blockified_msg = blockify_and_matrix_msg(hexified_msg)
    print(blockified_msg)

    print(key)
    tokenized_key = tokenize(key, 2)
    hexified_key = hexify(tokenized_key)
    blockified_key = blockify_and_matrix_msg(hexified_key)
    print(blockified_key)
    print("-------------------------")

    #Encrypt.encrypt(message, key)


if __name__ == "__main__":
    main()
