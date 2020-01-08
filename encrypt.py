import lookups

from pprint import pprint
from matrix import transpose, transpose_blocks


key_length = None
round_keys = None  # Index i corresponds to round i
num_rounds = 10
state = None
key_schedule = None
N_b = 4
N_k = None
s_box = lookups.sBox
mult_table = lookups.multTable

def hexify_state():
    hexed_list = [hex(j)[2:].rjust(2, '0') for i in state for j in i]
    #print(hexed_list)
    return "".join(hexed_list)

def encrypt(msg_, key_):
    global key_length
    global round_keys
    global N_k
    global state

    round_keys = [key_]

    state = msg_
    key = key_

    generate_key_schedule(key_)

    # Begin perform encryption of the first block
    only_first = (2, True)  # To perform all 10 rounds, change to (numRounds,False)

    state = add_round_key(state[0], get_round_key(0))  # Add initial key to message block
    print("round {} - state: {}".format(0, hexify_state()))
    for round_i in range(1, only_first[0]):
        state = byte_sub(state)
        print("round {} - bytesub: {}".format(round_i, hexify_state()))
        state = transpose(shift_row(transpose(state)))
        print("round {} - shift_row: {}".format(round_i, hexify_state()))
        state = transpose(mix_columns(transpose(state)))
        print("round {} - mix_columns: {}".format(round_i, hexify_state()))
        state = transpose(add_round_key(transpose(state), get_round_key(round_i)))
        print("round {} - add_round_key: {}".format(round_i, hexify_state()))

    if not only_first[1]:
        state = byte_sub(state)
        state = shift_row(state)
        state = add_round_key(state, get_round_key(0))
    # End encryption of first block

    ############################ begin D E B U G G I N G ###############################################
    a = get_round_key(1)
    for i in range(len(a)):
        for j in range(len(a[i])):  # TO PRINT ROUNDKEY IN HEX
            a[i][j] = hex(a[i][j])
    # print("ROUND KEY: ", a)

    for i in range(len(state)):
        for j in range(len(state[i])):  # TO PRINT STATE IN HEX FOR DEBUGGING
            state[i][j] = hex(state[i][j])

    for row in state:
        print(row)


############################ end D E B U G G I N G ###############################################


############################   Begin AES steps   #################################################
def byte_sub(state_):  # Replace each entry in the state matrix by its corresponding entry in the S-box
    for i in range(len(state_)):
        for j in range(len(state_[i])):
            state_[i][j] = s_box[state_[i][j]]
    return state_


def shift_row(state_):  # Rotate the ith row of the state matrix by i positions
    for row in range(len(state_)):
        state_[row] = rot_word(state_[row], row)
    return state_


def mix_columns(state_):
    """
    Multiplies the state matrix with the following matrix on the left:
    [x   x+1   1   1]
    [1   x   x+1   1]
    [1   1   x   x+1]
    [x+1   1   1   x]
    :param state_:
    :return:
    """
    state_prime = [[None] * 4, [None] * 4, [None] * 4, [None] * 4]
    for col in range(len(state_)):  # For the dot products of the row/column vectors, XOR elements instead of adding.
        state_prime[0][col] = mult_table[(0x2, state_[0][col])] ^ mult_table[(0x3, state_[1][col])] ^ state_[2][col] ^ \
                              state_[3][col]
        state_prime[1][col] = state_[0][col] ^ mult_table[(0x2, state_[1][col])] ^ mult_table[(0x3, state_[2][col])] ^ \
                              state_[3][col]
        state_prime[2][col] = state_[0][col] ^ state_[1][col] ^ mult_table[(0x2, state_[2][col])] ^ mult_table[
            (0x3, state_[3][col])]
        state_prime[3][col] = mult_table[(0x3, state_[0][col])] ^ state_[1][col] ^ state_[2][col] ^ mult_table[
            (0x2, state_[3][col])]
    return state_prime


def add_round_key(state_, key_):  # XOR the state matrix with the key matrix element-wise
    for i in range(len(state_)):
        state_[i] = xor_col(state_[i], key_[i])
    return state_


#############################   End AES steps   ##################################################


###############################   Below are helper functions   ###################################
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
    print("-"*25)
    pprint([[hex(a) for a in j] for j in w])
    print("-"*25)
    key_schedule = w


def get_round_key(cur_round):
    global key_schedule
    temp = [key_schedule[4 * cur_round + i] for i in range(4)]
    round_key = [[0 for x in range(4)] for y in range(4)]

    for row in range(len(temp)):  # Transpose matrix again since key_schedule is in terms of columns
        for col in range(len(temp[row])):
            round_key[row][col] = temp[col][row]
    return round_key


def round_const(cur_round):  # Return the round constant for round cur_round
    if cur_round == 1:
        return 1
    else:
        """ Returns the polynomial x^(curRound-1) in GF(256)/(x^8 + x^4 + x^3 + x + 1) """
        return mult_table[0x2, round_const(cur_round - 1)]


def rot_word(arr, n):  # left shift array by n. For example, rot_word([1,2,3,4], 1) returns [2,3,4,1]
    temp = []
    for i in range(n, len(arr) + n):
        temp.append(arr[i % len(arr)])
    return temp


def xor_col(col1, col2):  # Bitwise XOR 2 vectors instead of having to do it for each item manually
    temp = [0 for x in range(len(col1))]
    for i in range(len(col1)):
        temp[i] = col1[i] ^ col2[i]
    return temp


def transform_col(col, r_const):
    """
    Helper routine used in the generation of the key schedule. Rotates the columns by 1 position, substitutes the bytes
    in the columns with those in the S-box, then XORs the leftmost byte with the round constant
    :param col:
    :param r_const:
    :return:
    """
    temp = rot_word(col, 1)
    for i in range(len(temp)):
        temp[i] = s_box[temp[i]]
    temp[0] = temp[0] ^ r_const
    return temp
