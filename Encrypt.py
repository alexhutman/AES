import Lookups

keyLength = None
roundKeys = None #Index i corresponds to round i
numRounds = 10
state = None
keySchedule = None
N_b = 4
N_k = None
sBox = Lookups.sBox
multTable = Lookups.multTable

def encrypt(msg_,key_):
    global keyLength
    global roundKeys
    global N_k
    global state

    roundKeys = [key_]

    state = msg_
    key = key_

    genKeySchedule(key_)

# Begin perform encryption of the first block
    onlyFirst = (2, True)      # To perform all 10 rounds, change to (numRounds,False)

    state = addRoundKey(state[0], getRoundKey(0))     # Add initial key to message block
    for round_i in range(1,onlyFirst[0]):
        state = byteSub(state)
        state = shiftRow(state)
        state = mixColumns(state)
        state = addRoundKey(state, getRoundKey(round_i))

    if not onlyFirst[1]:
        state = byteSub(state)
        state = shiftRow(state)
        state = addRoundKey(state, getRoundKey(0))
# End encryption of first block

############################ begin D E B U G G I N G ###############################################
    a = getRoundKey(1)
    for i in range(len(a)):
        for j in range(len(a[i])): #TO PRINT ROUNDKEY IN HEX
            a[i][j] = hex(a[i][j])
    #print("ROUND KEY: ", a)

    for i in range(len(state)):
        for j in range(len(state[i])): #TO PRINT STATE IN HEX FOR DEBUGGING
            state[i][j] = hex(state[i][j])

    for row in state:
        print(row)
############################ end D E B U G G I N G ###############################################




############################   Begin AES steps   #################################################
def byteSub(state_):                          # Replace each entry in the state matrix by its corresponding entry in the S-box
    for i in range(len(state_)):
        for j in range(len(state_[i])):
            state_[i][j] = sBox[state_[i][j]]
    return state_

def shiftRow(state_):                          # Rotate the ith row of the state matrix by i positions
    for row in range(len(state_)):
        state_[row] = rotWord(state_[row],row)
    return state_

def mixColumns(state_):                                                                                                         # Multiplies the state matrix with the following matrix on the left:
    statePrime = [[None]*4,[None]*4,[None]*4,[None]*4]                                                                         # [x   x+1   1   1]
    for col in range(len(state_)):                                                                                             # [1   x   x+1   1]        for the dot products of the row/column vectors,
        statePrime[0][col] = multTable[(0x2,state_[0][col])]^multTable[(0x3,state_[1][col])]^state_[2][col]^state_[3][col]     # [1   1   x   x+1]        XOR elements instead of adding.
        statePrime[1][col] = state_[0][col]^multTable[(0x2,state_[1][col])]^multTable[(0x3,state_[2][col])]^state_[3][col]     # [x+1   1   1   x]
        statePrime[2][col] = state_[0][col]^state_[1][col]^multTable[(0x2,state_[2][col])]^multTable[(0x3,state_[3][col])]
        statePrime[3][col] = multTable[(0x3,state_[0][col])]^state_[1][col]^state_[2][col]^multTable[(0x2,state_[3][col])]
    return statePrime

def addRoundKey(state_, key_):                # XOR the state matrix with the key matrix element-wise
    for i in range(len(state_)):
        state_[i] = xorCol(state_[i],key_[i])
    return state_
#############################   End AES steps   ##################################################



###############################   Below are helper functions   ###################################
def genKeySchedule(key_):
    global keySchedule
    w = [[0 for x in range(4)] for y in range(44)]
    temp = [0 for x in range(4)]

    for row in range(len(key_)):
      for col in range(len(key_[row])): #Transpose key_, put into first 4 cols of w
          w[row][col] = key_[col][row]

    for i in range(4,44):
        if i%4 != 0:
            w[i] = xorCol(w[i-4],w[i-1])
        else:
            w[i] = xorCol(w[i-4],transformCol(w[i-1],roundConst(i//4)))
    keySchedule = w

def getRoundKey(curRound):
    global keySchedule
    temp = [keySchedule[4*curRound+i] for i in range(4)]
    roundKey = [[0 for x in range(4)] for y in range(4)]

    for row in range(len(temp)):    #Transpose matrix again since keySchedule is in terms of columns
      for col in range(len(temp[row])):
          roundKey[row][col] = temp[col][row]
    return roundKey

def roundConst(curRound): # Return the round constant for round curRound
    if curRound == 1:
        return 1
    else:
        return multTable[0x2,roundConst(curRound-1)]  # Returns the polynomial x^(curRound-1) in GF(256)/(x^8 + x^4 + x^3 + x + 1)

def rotWord(arr,n): #left shift array by n. For example, rotWord([1,2,3,4], 1) returns [2,3,4,1]
    temp = []
    for i in range(n,len(arr)+n):
        temp.append(arr[i%len(arr)])
    return temp

def xorCol(col1,col2): # Bitwise XOR 2 vectors instead of having to do it for each item manually
    temp = [0 for x in range(len(col1))]
    for i in range(len(col1)):
        temp[i] = col1[i]^col2[i]
    return temp

def transformCol(col, rConst): # Helper routine used in the generation of the key schedule. Rotates the columns by 1 position,
    temp = rotWord(col,1)      # substitutes the bytes in the columns with those in the S-box, then XORs the leftmost byte with the round constant
    for i in range(len(temp)):
        temp[i] = sBox[temp[i]]
    temp[0] = temp[0]^rConst
    return temp
