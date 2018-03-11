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

    #Last round is computed differently!!!! see https://csrc.nist.gov/csrc/media/projects/cryptographic-standards-and-guidelines/documents/aes-development/rijndael-ammended.pdf

    genKeySchedule(key_)
    state = addRoundKey(state[0], getRoundKey(0)) #TESTING 0TH BLOCK OF MESSAGE, BE SURE TO DO ALL BLOCKS!
    state = byteSub(state)
    state = shiftRow(state)
    state = mixColumn(state)
    state = addRoundKey(state, getRoundKey(1))


    a = getRoundKey(1)
    for i in range(len(a)):
        for j in range(len(a[i])): #TO PRINT STATE IN HEX FOR DEBUGGING
            a[i][j] = hex(a[i][j])
    #print("ROUND KEY: ", a)

    for i in range(len(state)):
        for j in range(len(state[i])): #TO PRINT STATE IN HEX FOR DEBUGGING
            state[i][j] = hex(state[i][j])

    print(state)

def addRoundKey(state_, key_):
    for i in range(len(state_)):
        state_[i] = xorCol(state_[i],key_[i])
    return state_

#def addRoundKey(state_, key_):
#    for i in range(len(state_)):
#        for j in range(len(state_[i])):
#            state_[i][j] = state_[i][j]^key_[i][j]
#    return state_

def byteSub(state_):
    for i in range(len(state_)):
        for j in range(len(state_[i])):
            state_[i][j] = sBox[state_[i][j]]
    return state_

def shiftRow(state_):
    for row in range(len(state_)):
        state_[row] = rotWord(state_[row],row)
    return state_

def mixColumn(state_):
    statePrime = [[None]*4,[None]*4,[None]*4,[None]*4]
    for col in range(len(state_)):
        statePrime[0][col] = multTable[(0x2,state_[0][col])]^multTable[(0x3,state_[1][col])]^state_[2][col]^state_[3][col]
        statePrime[1][col] = state_[0][col]^multTable[(0x2,state_[1][col])]^multTable[(0x3,state_[2][col])]^state_[3][col]
        statePrime[2][col] = state_[0][col]^state_[1][col]^multTable[(0x2,state_[2][col])]^multTable[(0x3,state_[3][col])]
        statePrime[3][col] = multTable[(0x3,state_[0][col])]^state_[1][col]^state_[2][col]^multTable[(0x2,state_[3][col])]
    return statePrime

def genKeySchedule(key_):  #NNNNNNOOOOOOOOTTTTTTT DDDDDDOOOOOOOOONNNNNNNNNEEEEEEEEE
    global keySchedule
    w = [[0 for x in range(4)] for y in range(44)]
    temp = [0 for i in range(4)]

    for row in range(len(key_)):
      for col in range(len(key_[row])): #Transpose key_, put into first 4 cols of w
          w[row][col] = key_[col][row]

    for i in range(4,44):
        if i%4 != 0:
            w[i] = xorCol(w[i-4],w[i-1])
        else:
            w[i] = xorCol(w[i-4],transformCol(w[i-1],roundConst(i//4)))
        #temp = w[i-1]
        #if i%4==0:
        #    for j in range(4):
        #        temp[j] = sBox[rotWord(temp,1)[j]]^roundConst(i//4)
        #for k in range(4):
        #    w[i][k] = w[i-4][k]^temp[k]
    keySchedule = w

def getRoundKey(curRound):
    global keySchedule
    temp = [keySchedule[4*curRound+i] for i in range(4)]
    roundKey = [[0 for x in range(4)] for y in range(4)]

    for row in range(len(temp)):    #Transpose matrix again since keySchedule is in terms of columns
      for col in range(len(temp[row])):
          roundKey[row][col] = temp[col][row]
    return roundKey

def roundConst(curRound):
    if curRound == 1:
        return 1
    else:
        return multTable[0x2,roundConst(curRound-1)]

def rotWord(arr,n): #left shift by n
    temp = []
    for i in range(n,len(arr)+n):
        temp.append(arr[i%len(arr)])
    return temp

def xorCol(col1,col2):
    temp = [0 for x in range(len(col1))]
    for i in range(len(col1)):
        temp[i] = col1[i]^col2[i]
    return temp

def transformCol(col, rConst):
    temp = rotWord(col,1)
    for i in range(len(temp)):
        temp[i] = sBox[temp[i]]
    temp[0] = temp[0]^rConst
    return temp
