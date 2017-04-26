import math
import copy
import sys

from RSAEncryption import *

if __name__ == "__main__":
    rsa = RSAEncryption(961748941, 982451653, 31)

    message = "Hello, world! This is Darren and Judy and Christina."
    ciphertext = rsa.encrypt(message)
    decoded_message = rsa.decrypt(ciphertext)

    print("Message: " + message)
    print("Ciphertext: " + str(ciphertext))
    print("Decrypted text: " + decoded_message)