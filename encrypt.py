import lookups

from pprint import pprint
from matrix import transpose, transpose_blocks


class Encrypt:
    def __init__(self, key_length):
        valid_lengths = [128, 192, 256] # in bits
        if key_length not in valid_lengths:
            raise Exception(f"KeyLengthException: Key length must be either {', '.join([str(x) for x in valid_lengths[:-1]])}, or {str(valid_lengths[-1])} bits long (got {key_length}).")
        else:
            self.key_length = key_length

        self.num_columns = 4  # Defined in the standard as N_b
        self.num_words = self.key_length // 32 # Defined in the standard as N_k
        self.num_rounds = { # Defined in the standard as N_r
                128: 10,
                192: 12,
                256: 14
                }[self.key_length]

    @staticmethod()
    def generate_key_schedule(key):
        rconst = Encrypt.gen_round_consts()
        print("-"*25)
        print("KEY:")
        pprint([[hex(a) for a in j] for j in key])
        print("-"*25)

        w = [[0 for x in range(4)] for y in range(4*11)]

        for i in range(4*11): #TODO: change 11 to num_round keys needed
            print(f"i = {i}")
            if i<4: #TODO: change 4 to num_words
                w[i] = key[i]           
            elif i >= 4 and i % 4 == 0:
                w[i] = Encrypt.xor_col(w[i - 4], Encrypt.transform_col(w[i - 1], rconst[(i // 4) - 1]))
            elif i >= 4 and 4 > 6 and i % N == 4:
                w[i] = Encrypt.xor_col(w[i - 4], [s_box(x) for x in w[i-1]])
            else:
                w[i] = Encrypt.xor_col(w[i - 4], w[i-1])


        print("-"*25)
        pprint([[hex(a) for a in j] for j in w])
        print("-"*25)
        return w

    @staticmethod
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

    @staticmethod
    def byte_sub(state):  # Replace each entry in the state matrix by its corresponding entry in the S-box
        for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] = s_box[state[i][j]]
        return state

    @staticmethod
    def shift_row(state):  # Rotate the ith row of the state matrix by i positions
        for row in range(len(state)):
            state[row] = rot_word(state[row], row)
        return state

    @staticmethod
    def mix_columns(state):
        """
        Multiplies the state matrix with the following matrix on the left:
        [x   x+1   1   1]
        [1   x   x+1   1]
        [1   1   x   x+1]
        [x+1   1   1   x]
        :param state:
        :return:
        """
        state_prime = [[None] * 4, [None] * 4, [None] * 4, [None] * 4]
        for col in range(len(state)):  # For the dot products of the row/column vectors, XOR elements instead of adding.
            state_prime[0][col] = mult_table[(0x2, state[0][col])] ^ mult_table[(0x3, state[1][col])] ^ state[2][col] ^ \
                                  state[3][col]
            state_prime[1][col] = state[0][col] ^ mult_table[(0x2, state[1][col])] ^ mult_table[(0x3, state[2][col])] ^ \
                                  state[3][col]
            state_prime[2][col] = state[0][col] ^ state[1][col] ^ mult_table[(0x2, state[2][col])] ^ mult_table[
                (0x3, state[3][col])]
            state_prime[3][col] = mult_table[(0x3, state[0][col])] ^ state[1][col] ^ state[2][col] ^ mult_table[
                (0x2, state[3][col])]
        return state_prime

    @staticmethod
    def add_round_key(state, key):  # XOR the state matrix with the key matrix element-wise
        for i in range(len(state)):
            state[i] = xor_col(state[i], key[i])
        return state

    @staticmethod
    def get_round_key(cur_round):
        global key_schedule
        temp = [key_schedule[4 * cur_round + i] for i in range(4)]
        round_key = [[0 for x in range(4)] for y in range(4)]

        for row in range(len(temp)):  # Transpose matrix again since key_schedule is in terms of columns
            for col in range(len(temp[row])):
                round_key[row][col] = temp[col][row]
        return round_key


    @staticmethod
    def round_const(cur_round):  # Return the round constant for round cur_round
        if cur_round == 1:
            return 1
        else:
            """ Returns the polynomial x^(curRound-1) in GF(256)/(x^8 + x^4 + x^3 + x + 1) """
            return mult_table[0x2, round_const(cur_round - 1)]


    @staticmethod
    def rot_word(arr, n):  # left shift array by n. For example, rot_word([1,2,3,4], 1) returns [2,3,4,1]
        temp = []
        for i in range(n, len(arr) + n):
            temp.append(arr[i % len(arr)])
        return temp


    @staticmethod
    def xor_col(col1, col2):  # Bitwise XOR 2 vectors instead of having to do it for each item manually
        temp = [0 for x in range(len(col1))]
        for i in range(len(col1)):
            temp[i] = col1[i] ^ col2[i]
        return temp


    @staticmethod
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

    @staticmethod
    def encrypt(msg, key):
        global key_length
        global round_keys
        global N_k
        global state
        global rconst

        round_keys = [key]

        state = msg
        
        rconst = gen_round_consts()
        generate_key_schedule(key)

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

def hexify_state(state):
    hexed_list = [hex(j)[2:].rjust(2, '0') for i in state for j in i]
    #print(hexed_list)
    return "".join(hexed_list)

