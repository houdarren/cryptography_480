# RSA Implementation DONE

import math
import sys
import random 
from fractions import gcd

def calcN(p,q):
    return p*q

def calcPhi(p,q):
   return (p-1)*(q-1)

def choose_e(phi, lst):
    eNow = random.choice(lst)
    while gcd(eNow,phi) != 1:
        eNow = random.choice(lst)
    return eNow
        
def createPubKeys(phi):
    """
    This function will generate/return public key
    """
    lst = list(range(3,phi))
    e = choose_e(phi,lst) # (e,n) public key
    return e
    
def createPrivKeys(e, phi):
    """
    This function will generate/return private key
    """
    d = multInverse(e, phi)
    return d

def multInverse(e, phi):
    x = e % phi
    for i in range(1,phi) :
        if((x * i) % phi == 1) :
            return i
            
def encryption(m):
    """
    This function creates encrypted message (ciphertext)
    """
    encryptM = [(ord(c) ** e % n) for c in m]
    return encryptM

def decryption(c):
    """
    This function decrypts the ciphertext to the original message 
    """
    decryptM = [chr(char ** d % n) for char in c]
    return ''.join(decryptM)

p = 23 # p can be changed
q = 29 # q can be changed
n = calcN(p,q)
phi = calcPhi(p,q)
e = createPubKeys(phi)
d = createPrivKeys(e, phi)

message = raw_input("Please enter your desired message to be encrypted: ")

#assert decryption(encryption(message)) == message

print "Decrypted Message is:", decryption(encryption(message))
     
     
       
