# CNT4406 Project: Implementing the Triple DES Encryption Algorithm

This project implements the triple DES encryption algorithm. The main function takes in a plaintext string from standard input, and uses three randomly generated 64-bit keys to apply 3 iterations of the DES encryption algorithm. This algorithm utilizes bitwise operations and permutations of the bits to accomplish the encryption.

The program prints out the encrypted ciphertext, and then uses the same keys to decrypt the message and print out the decrypted plaintext.

The DES algorithm implements Key Scheduling, inital permutation of the plaintext, 16 rounds of the DES Feistel function using 16 different round keys, and a final permutation. This algorithm can encrypt strings of any length; the algorithm splits the plaintext up into 64-bit blocks for processing. 

The Key Scheduling function takes in the randomly generated 64-bit key, applies PC-2 permutation to go from 64-bit to 56-bit, and uses the new 56-bit key to generate sixteen different 48-bit keys, one for each round of the Feistel function.

The DES Feistel function includes:
* splitting block into 32-bit halves (right half becomes the left half for next round)
* expansion permutation on the right half to go from 32-bit to 48-bit
* XOR right half with the round key
* S-box substitution to go from 48-bit to 32-bit
* intermediate permutation on right half
* XOR right half with left half (left half becomes the right half for next round)

The encryption function takes in the plaintext and the randomly generated 64-bit key as parameters, and returns the ciphertext.

The decryption function takes in the same key as used for encryption and the ciphertext, and returns the plaintext. Decryption implements the same exact process as the encryption algorithm. The only difference between encryption and decryption is that decryption uses the sixteen round keys in reverse order.

The permutation orders for key generation, initial permutation, intermediate permutation, expansion permutation, PC-2, and the S1-S8 S-boxes are included at the top of the file in the form of arrays. These permutation orders are standard and were obtained from https://en.wikipedia.org/wiki/DES_supplementary_material.
