import lookups

from pprint import pprint
from matrix import transpose, transpose_blocks

class Encrypt:
    def __init__(self, key_len):
        self.N_b = 4  # Number of columns. Defined in the standard as 4

        self.key_length = key_len

    def encrypt(self, msg, key):
        print("-"*25)
        print("MSG:")
        pprint(msg)
        print("-"*25)
        print("KEY:")
        pprint(key)
        print("-"*25)
        
        self.__validate_key(key, self.key_length)
        self.N_k, self.N_r = self.__calculate_constants(key, self.key_length)


        self.key_schedule = self.__generate_key_schedule(key)
        print("-"*25)
        print("KEY SCHEDULE:")
        pprint([[hex(a) for a in row] for row in self.key_schedule])
        print("-"*25)

        encrypted_blocks = []

        for block in msg:
            state = self.__add_round_key(block, self.__get_round_key(0))  # Add initial key to message block

            print("round {} - state: {}".format(0, hexify_state(state)))
            for round_i in range(1, self.N_r+1):
                state = self.__byte_sub(state)
                print("round {} - bytesub: {}".format(round_i, hexify_state(state)))
                state = transpose(self.__shift_row(transpose(state)))
                print("round {} - shift_row: {}".format(round_i, hexify_state(state)))
                if round_i != self.N_r:
                    state = transpose(self.__mix_columns(transpose(state)))
                    print("round {} - mix_columns: {}".format(round_i, hexify_state(state)))

                print("-"*25)
                print(f"ROUND KEY FOR ROUND {round_i}:")
                r_key = self.__get_round_key(round_i)
                print(hexify_state(r_key))
                print("-"*25)

                state = self.__add_round_key(state, r_key)
                print("round {} - add_round_key: {}".format(round_i, hexify_state(state)))

            encrypted_blocks.append(state)

        return "".join([hexify_state(enc_block) for enc_block in encrypted_blocks])

    @staticmethod
    def __validate_key(key, key_length):
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

    @staticmethod
    def __calculate_constants(key, key_length):
        num_rounds = { # Defined in the standard as N_r
                128: 10,
                192: 12,
                256: 14
        }
        print(f"KEY LEN: {len(key)}")
        print(f"KEY: {key}")
        if key_length not in num_rounds:
            raise Exception(f"KeyLengthException: Key length must be either {', '.join([str(x) for x in num_rounds[:-1]])}, or {str(num_rounds[-1])} bits long (got {key_length}).")

        given_key_length = 8 * len(key) # Assuming key is an array of bytes
        if given_key_length != key_length:
            raise Exception(f"KeyLengthException: Key length must be {key_length} long (got {given_key_length} bits).")

        N_k = key_length // 32 # Defined in the standard as being the number of words in the key
        N_r = num_rounds[key_length] # Defined in the standard as being the number of rounds needed for the given key length
        return N_k, N_r

    def __generate_key_schedule(self, key): #TODO: add key_length as a parameter to generate only necessary round constants
        Rcon = self.__generate_round_consts()

        w = []
        print(f"4*N_r: {4*self.N_r}")
        for i in range(4*(self.N_r+1)): #TODO: change 11 to num_round keys needed
            #print(f"i = {i}")
            if i < self.N_k:
                print("Case 1")
                w.append(key[4*i:4*i+4])
            elif i >= self.N_k and i % self.N_k == 0:
                print("Case 2")
                w.append(Encrypt.__xor_col(w[i - self.N_k], Encrypt.__transform_col(w[i - 1], Rcon[(i // self.N_k) - 1])))
            elif i >= self.N_k and self.N_k > 6 and i % self.N_k == 4:
                print("Case 3")
                w.append(Encrypt.__xor_col(w[i - self.N_k], [lookups.s_box[x] for x in w[i-1]]))
            else:
                print("Case 4")
                w.append(Encrypt.__xor_col(w[i - self.N_k], w[i-1]))
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

    def __get_round_key(self, cur_round):
        return self.key_schedule[4*cur_round:4*cur_round+4]

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


class AES128(Encrypt):
    def __init__(self):
        super().__init__(128)

class AES192(Encrypt):
    def __init__(self):
        super().__init__(192)

class AES256(Encrypt):
    def __init__(self):
        super().__init__(256)

