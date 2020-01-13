import lookups

from pprint import pprint
from matrix import transpose, transpose_blocks


class Encrypt:
    @staticmethod
    def AES128(msg, key):
        return Encrypt.__encrypt(msg, key, 128)

    @staticmethod
    def AES192(msg, key):
        return Encrypt.__encrypt(msg, key, 192)

    @staticmethod
    def AES256(msg, key):
        return Encrypt.__encrypt(msg, key, 256)

    @staticmethod
    def __encrypt(msg, key, key_length):
        print("-"*25)
        print("MSG:")
        pprint(msg)
        print("-"*25)
        print("KEY:")
        pprint(key)
        print("-"*25)

        N_b = 4  # Number of columns. Defined in the standard as 4
        N_k, N_r = Encrypt.__calculate_constants(key, key_length)

        key_schedule = Encrypt.__generate_key_schedule(key)
        print("-"*25)
        print("KEY SCHEDULE:")
        pprint(key_schedule)
        print("-"*25)

        state = Encrypt.__add_round_key(msg[0], Encrypt.__get_round_key(0, key_schedule))  # Add initial key to message block

        #TODO: Add support for multiple blocks
        print("round {} - state: {}".format(0, hexify_state(state)))
        #for round_i in range(1, N_r+1):
        for round_i in range(1, N_r+1):
            state = Encrypt.__byte_sub(state)
            print("round {} - bytesub: {}".format(round_i, hexify_state(state)))
            state = transpose(Encrypt.__shift_row(transpose(state)))
            print("round {} - shift_row: {}".format(round_i, hexify_state(state)))
            if round_i != N_r:
                state = transpose(Encrypt.__mix_columns(transpose(state)))
                print("round {} - mix_columns: {}".format(round_i, hexify_state(state)))

            print("-"*25)
            print(f"ROUND KEY FOR ROUND {round_i}:")
            r_key = Encrypt.__get_round_key(round_i, key_schedule)
            print(hexify_state(r_key))
            print("-"*25)

            state = Encrypt.__add_round_key(state, r_key)
            print("round {} - add_round_key: {}".format(round_i, hexify_state(state)))

        return state

    @staticmethod
    def __calculate_constants(key, key_length):
        num_rounds = { # Defined in the standard as N_r
                128: 10,
                192: 12,
                256: 14
        }
        if key_length not in num_rounds:
            raise Exception(f"KeyLengthException: Key length must be either {', '.join([str(x) for x in num_rounds[:-1]])}, or {str(num_rounds[-1])} bits long (got {key_length}).")

        given_key_length = 8 * len(key) # Assuming key is an array of bytes
        if given_key_length != key_length:
            raise Exception(f"KeyLengthException: Key length must be {key_length} long (got {given_key_length} bits).")

        N_k = key_length // 32 # Defined in the standard as being the number of words in the key
        N_r = num_rounds[key_length] # Defined in the standard as being the number of rounds needed for the given key length
        return N_k, N_r

    @staticmethod
    def __generate_key_schedule(key): #TODO: add key_length as a parameter to generate only necessary round constants
        Rcon = Encrypt.__generate_round_consts()

        w = []
        for i in range(4*11): #TODO: change 11 to num_round keys needed
            #print(f"i = {i}")
            if i<4: #TODO: change 4 to num_words
                w.append(key[4*i:4*i+4])
            elif i >= 4 and i % 4 == 0:
                w.append(Encrypt.__xor_col(w[i - 4], Encrypt.__transform_col(w[i - 1], Rcon[(i // 4) - 1])))
            elif i >= 4 and 4 > 6 and i % N == 4:
                w.append(Encrypt.__xor_col(w[i - 4], [lookups.s_box(x) for x in w[i-1]]))
            else:
                w.append(Encrypt.__xor_col(w[i - 4], w[i-1]))
            #print(f"w[{i}] = {''.join([hex(a)[2:].rjust(2, '0') for a in w[i]])}")

        return w

    @staticmethod
    def __generate_round_consts(): #TODO: add key_length as a parameter to generate only necessary round constants
        rc = []
        for i in range(10):
            if i == 0:
                rc.append(1)
            elif i > 0 and rc[i-1] < 0x80:
                rc.append(2*rc[i-1])
            elif i > 0 and rc[i - 1] >= 0x80:
                rc.append(((2*rc[i-1]) ^ 0x1B) & 0xFF) # Masking with 0xFF because elements in GF256 are 8 bits long
        return rc

    @staticmethod
    def __byte_sub(state):  # Replace each entry in the state matrix by its corresponding entry in the S-box
        for i in range(len(state)):
            for j in range(len(state[i])):
                state[i][j] = lookups.s_box[state[i][j]]
        return state

    @staticmethod
    def __shift_row(state):  # Rotate the ith row of the state matrix by i positions
        for row in range(len(state)):
            state[row] = Encrypt.__rot_word(state[row], row)
        return state

    @staticmethod
    def __mix_columns(state):
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
            state_prime[0][col] = lookups.mult_table[(0x2, state[0][col])] ^ lookups.mult_table[(0x3, state[1][col])] ^ state[2][col] ^ \
                                  state[3][col]
            state_prime[1][col] = state[0][col] ^ lookups.mult_table[(0x2, state[1][col])] ^ lookups.mult_table[(0x3, state[2][col])] ^ \
                                  state[3][col]
            state_prime[2][col] = state[0][col] ^ state[1][col] ^ lookups.mult_table[(0x2, state[2][col])] ^ lookups.mult_table[
                (0x3, state[3][col])]
            state_prime[3][col] = lookups.mult_table[(0x3, state[0][col])] ^ state[1][col] ^ state[2][col] ^ lookups.mult_table[
                (0x2, state[3][col])]
        return state_prime

    @staticmethod
    def __add_round_key(state, round_key):  # XOR the state matrix with the key matrix element-wise
        #for i in range(len(state)):
            #state[i] = Encrypt.__xor_col(state[i], round_key[i])
        print("-"*25)
        print("ADDING STATE AND KEY:")
        pprint(hexify_state(state))
        pprint(hexify_state(round_key))
        print("-"*25)
        return [Encrypt.__xor_col(state[i], round_key[i]) for i in range(len(round_key))]

    @staticmethod
    def __get_round_key(cur_round, key_schedule):
        return key_schedule[4*cur_round:4*cur_round+4]

    @staticmethod
    def __round_const(cur_round):  # Return the round constant for round cur_round
        if cur_round == 1:
            return 1
        else:
            """ Returns the polynomial x^(curRound-1) in GF(256)/(x^8 + x^4 + x^3 + x + 1) """
            return lookups.mult_table[0x2, __round_const(cur_round - 1)]

    @staticmethod
    def __rot_word(arr, n):  # left shift array by n. For example, __rot_word([1,2,3,4], 1) returns [2,3,4,1]
        temp = []
        for i in range(n, len(arr) + n):
            temp.append(arr[i % len(arr)])
        return temp


    @staticmethod
    def __xor_col(col1, col2):  # Bitwise XOR 2 vectors instead of having to do it for each item manually
        temp = [0 for x in range(len(col1))]
        for i in range(len(col1)):
            temp[i] = col1[i] ^ col2[i]
        return temp


    @staticmethod
    def __transform_col(col, r_const):
        """
        Helper routine used in the generation of the key schedule. Rotates the columns by 1 position, substitutes the bytes
        in the columns with those in the S-box, then XORs the leftmost byte with the round constant
        :param col:
        :param r_const:
        :return:
        """
        temp = Encrypt.__rot_word(col, 1)
        for i in range(len(temp)):
            temp[i] = lookups.s_box[temp[i]]
        temp[0] = temp[0] ^ r_const
        return temp

def hexify_state(state):
    hexed_list = [hex(j)[2:].rjust(2, '0') for i in state for j in i]
    #print(hexed_list)
    return "".join(hexed_list)

