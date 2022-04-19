
import random
import string
from datetime import datetime

# Constants
BITLEN64 = 64
BITLEN48 = 48
BITLEN32 = 32
KEYLEN56 = 56
KEYLEN48 = 48
KEYLEN28 = 28

currentround = 1

# key generation permutation table
KP = [57, 49, 41, 33, 25, 17, 9, 1,
      58, 50, 42, 34, 26, 18, 10, 2,
      59, 51, 43, 35, 27, 19, 11, 3,
      60, 52, 44, 36, 63, 55, 47, 39,
      31, 23, 15, 7, 62, 54, 46, 38,
      30, 22, 14, 6, 61, 53, 45, 37,
      29, 21, 13, 5, 28, 20, 12, 4]

# initial permutation
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# final permutation
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# expansion permutation
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# permutation function
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# permutated choice 2
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# S1 SBOX
SBOX1 = [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
         [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
         [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
         [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]]

# S2 SBOX
SBOX2 = [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 1, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]]

# S3 SBOX
SBOX3 = [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]]

# S4 SBOX
SBOX4 = [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]]

# S5 SBOX
SBOX5 = [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [1, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]]

# S6 SBOX
SBOX6 = [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]]

# S7 SBOX
SBOX7 = [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]

# S8 SBOX
SBOX8 = [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]

# index+1 is the round # of DES
NumRotations = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]


# checks if the nth bit of an int is set
def is_nth_bit_set(x: int, n: int):
    if x & (1 << (n - 1)):
        return True
    return False


# sets the nth bit of an int
def set_nth_bit(x: int, n: int):
    return x | (1 << n)


# unsets the nth bit of an int
def unset_nth_bit(x: int, n: int):
    return x & (0 << n)


# takes in 64bit key, returns a list of (16) 48bit keys for each DES round
def keyScheduling(_64key):
    # convert to binary
    _64key = ''.join(format(ord(i), '08b') for i in _64key)

    # convert to int
    _64key = int(_64key, base=2)

    _56key = 0
    KPOFFSET64 = 65
    KPOFFSET56 = 55

    # KP permutation for key, go from 64bit to 56bit
    for i in range(KEYLEN56):
        if is_nth_bit_set(_64key, KPOFFSET64 - KP[i]):
            _56key = set_nth_bit(_56key, KPOFFSET56 - i)

    _28keys = []

    # split key into two 28b halves
    firsthalf = (_56key >> KEYLEN28) & 0xFFFFFFF
    secondhalf = _56key & 0xFFFFFFF

    # rotate and add the first pair of 28bit keys to list using the initial halves for rotation
    c = rotateleftN(firsthalf, KEYLEN28, NumRotations[0])
    d = rotateleftN(secondhalf, KEYLEN28, NumRotations[0])

    temptuple = c, d
    _28keys.append(temptuple)

    # rotate and add the rest of the 28bit keys to the list using the previous key for rotation
    for i in range(1, 16):
        c = rotateleftN(_28keys[i - 1][0], KEYLEN28, NumRotations[i])
        d = rotateleftN(_28keys[i - 1][1], KEYLEN28, NumRotations[i])

        temptuple = c, d
        _28keys.append(temptuple)

    _56keys = []

    # add bit halves back together to create (16) 56bit keys
    for i in _28keys:
        key = (i[0] << KEYLEN28) + i[1]
        _56keys.append(key)

    _48keys = []

    PC2OFFSET56 = 57
    PC2OFFSET48 = 47

    # apply PC2 permutation to each of the 56bit keys to form (16) 48bit keys
    for i in range(len(_56keys)):
        _48key = 0
        for j in range(KEYLEN48):
            if is_nth_bit_set(_56keys[i], PC2OFFSET56 - PC2[j]):
                _48key = set_nth_bit(_48key, PC2OFFSET48 - j)

        _48keys.append(_48key)

    # if reverse:
    #     return list(reversed(_48keys))
    # else:
    #     return _48keys

    return _48keys


# rotate the bits of an int to the left, n times
def rotateleftN(num, bits, numrotations):
    result = num
    for s in range(numrotations):
        result = rotateleft(result, bits)

    return result


# rotate the bits of an int to the left, once
def rotateleft(num, bits):
    bit = num & (1 << (bits - 1))
    num <<= 1
    if bit:
        num |= 1
    num &= (2 ** bits - 1)

    return num


def roundFunction(num, key):
    # split num into two 32bit halves
    lefthalf = (num >> BITLEN32) & 0xFFFFFFFF
    righthalf = num & 0xFFFFFFFF

    expanded = 0

    OFFSET32 = 33
    OFFSET48 = 47

    for i in range(BITLEN48):
        if is_nth_bit_set(righthalf, OFFSET32 - E[i]):
            expanded = set_nth_bit(expanded, OFFSET48 - i)

    # XOR with the round key
    xor48 = expanded ^ key

    # use SBOX to go from 48bit to 32bit

    # split xor48 into eight 6bit chunks
    chunks = list((xor48 >> i) & 63 for i in range(0, 48, 6))
    chunks = list(reversed(chunks))
    subs = []
    currentchunk = 0

    # substitute the bits in each chunk using S-boxes
    for chunk in chunks:

        # keeps track of chunk number to use correct SBOX
        currentchunk += 1

        # get SBOX row based on bits 1 and 6
        sbox_row = 0
        if is_nth_bit_set(chunk, 6):
            sbox_row += 2
        if is_nth_bit_set(chunk, 1):
            sbox_row += 1

        # get SBOX column based on bits 2-5
        sbox_column = 0
        for i in range(2, 6):
            if is_nth_bit_set(chunk, i):
                sbox_column = set_nth_bit(sbox_column, i - 2)

        # depending on chunk, use corresponding SBOX
        if currentchunk == 1:
            subs.append(SBOX1[sbox_row][sbox_column])
        elif currentchunk == 2:
            subs.append(SBOX2[sbox_row][sbox_column])
        elif currentchunk == 3:
            subs.append(SBOX3[sbox_row][sbox_column])
        elif currentchunk == 4:
            subs.append(SBOX4[sbox_row][sbox_column])
        elif currentchunk == 5:
            subs.append(SBOX5[sbox_row][sbox_column])
        elif currentchunk == 6:
            subs.append(SBOX6[sbox_row][sbox_column])
        elif currentchunk == 7:
            subs.append(SBOX7[sbox_row][sbox_column])
        elif currentchunk == 8:
            subs.append(SBOX8[sbox_row][sbox_column])

    # combine substituted chunks back into 48bits
    combined = 0

    SHIFTAMT28 = 28
    CHUNKLEN4 = 4

    for i in range(len(subs)):
        combined = combined + (subs[i] << (SHIFTAMT28 - (CHUNKLEN4 * i)))

    IPOFFSET32 = 31

    # intermediate permutation
    permutated = 0

    for i in range(BITLEN32):
        if is_nth_bit_set(combined, OFFSET32 - P[i]):
            permutated = set_nth_bit(permutated, IPOFFSET32 - i)

    # xor with lefthalf, righthalf becomes lefthalf for next round
    xor32 = permutated ^ lefthalf
    lefthalf = righthalf
    righthalf = xor32

    # put halves back together, return 64bit value for next round
    endvalue = (lefthalf << 32) + righthalf
    return endvalue


def encrypt(plaintext, key):
    str_blocks = []
    bin_blocks = []
    int_blocks = []
    blocksize = 8

    # split text into 8-character blocks
    for index in range(0, len(plaintext), blocksize):
        str_blocks.append(plaintext[index: index + blocksize])

    for block in str_blocks:
        # convert to binary
        block = ''.join(format(ord(i), '08b') for i in block)

        # pad zeroes if needed
        if len(block) != 64:
            zeroes = ""
            for i in range(len(block), 64):
                zeroes += "0"
            block = block + zeroes

        # add to binary blocks
        bin_blocks.append(block)

    for block in bin_blocks:
        # convert to int
        block = int(block, base=2)
        int_blocks.append(block)

    encrypted_blocks = []

    for block in int_blocks:
        # apply DES to each block
        encrypted_blocks.append(DES(block, key, True))

    chrchunks = []

    for block in encrypted_blocks:
        # split into eight 8bit chunks
        chunks = list((block >> i) & 255 for i in range(0, 64, 8))
        chunks = list(reversed(chunks))
        chrchunks.append(chunks)

    cyphertext = ""
    for chunks in chrchunks:
        for i in chunks:
            cyphertext += chr(i)

    return cyphertext


def decrypt(cyphertext, key):
    str_blocks = []
    bin_blocks = []
    int_blocks = []
    blocksize = 8

    # split text into 8-character blocks
    for index in range(0, len(cyphertext), blocksize):
        str_blocks.append(cyphertext[index: index + blocksize])

    for block in str_blocks:
        # convert to binary
        block = ''.join(format(ord(i), '08b') for i in block)

        # pad zeroes if needed
        if len(block) != 64:
            zeroes = ""
            for i in range(len(block), 64):
                zeroes += "0"
            block = block + zeroes

        # add to binary blocks
        bin_blocks.append(block)

    for block in bin_blocks:
        # convert to int
        block = int(block, base=2)
        int_blocks.append(block)

    decrypted_blocks = []

    for block in int_blocks:
        # apply DES to each block
        decrypted_blocks.append(DES(block, key, False))

    chrchunks = []

    for block in decrypted_blocks:
        # split into eight 8bit chunks
        chunks = list((block >> i) & 255 for i in range(0, 64, 8))
        chunks = list(reversed(chunks))
        chrchunks.append(chunks)

    plaintext = ""
    for chunks in chrchunks:
        for i in chunks:
            plaintext += chr(i)

    # remove trailing null characters from plaintext output
    plaintext = plaintext.rstrip(' \t\r\n\0')

    return plaintext


def DES(num, key, encrypt):
    roundkeys = keyScheduling(key)

    if not encrypt:
        roundkeys = list(reversed(roundkeys))

    ip = 0

    # IP permutation for num
    for i in range(BITLEN64):
        if is_nth_bit_set(num, 65 - IP[i]):
            ip = set_nth_bit(ip, 63 - i)

    # first iteration of round function
    permutated = roundFunction(ip, roundkeys[0])

    # 16 iterations of the round function
    for i in range(1, 16):
        permutated = roundFunction(permutated, roundkeys[i])

    # switch the left and right halves one more time

    lefthalf = (permutated >> BITLEN32) & 0xFFFFFFFF
    righthalf = permutated & 0xFFFFFFFF
    temp = lefthalf
    lefthalf = righthalf
    righthalf = temp
    permutated_new = (lefthalf << 32) + righthalf

    # apply final permutation
    endvalue = 0
    OFFSET64 = 65
    FPOFFSET64 = 63

    for i in range(BITLEN64):
        if is_nth_bit_set(permutated_new, OFFSET64 - FP[i]):
            endvalue = set_nth_bit(endvalue, FPOFFSET64 - i)

    return endvalue


if __name__ == "__main__":

    seed = str(datetime.now())
    random.seed(seed)

    user_input = ""

    while 1:
        user_input = input("Enter a string to encrypt ('exit' to quit): ")

        if user_input == "exit":
            break

        # first round of DES

        # generate random 64bit key (gets reduced to 56bit in key scheduling)
        key1 = ''
        key1 = key1.join(random.choices(string.ascii_letters + string.digits, k=8))

        ciphertext1 = encrypt(user_input, key1)

        # second round of DES
        # generate random 64bit key (gets reduced to 56bit in key scheduling)
        key2 = ''
        key2 = key2.join(random.choices(string.ascii_letters + string.digits, k=8))

        ciphertext2 = encrypt(ciphertext1, key2)

        # third round of DES
        # generate random 64bit key (gets reduced to 56bit in key scheduling)
        key3 = ''
        key3 = key3.join(random.choices(string.ascii_letters + string.digits, k=8))

        ciphertext3 = encrypt(ciphertext2, key3)

        print("Encrypted text: ", ciphertext3)

        decrypt1 = decrypt(ciphertext3, key3)
        decrypt2 = decrypt(decrypt1, key2)
        decrypt3 = decrypt(decrypt2, key1)

        # plaintext = decrypt(ciphertext, key)
        print("Decrypted text: ", decrypt3)

