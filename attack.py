import math
import copy
import time
import random
import sys

from encryption import *

# time how long attack takes
TIME_ATTACKS = True

ATTACKS_PER_BIT = 10000

def attack_decrypt(rsa, oracle):
    start_time = time.clock() * 1000
    rsa.decrypt([oracle])
    end_time = time.clock() * 1000

    return end_time - start_time


def attack_square(rsa, attacks):
    """Attacks the square portion of the square-and-multiply
    algorithm
    """
    timings = {}

    if attacks <= 0:
        return timings

    (public_n, public_e) = rsa.get_public_keys()
    bitwise_n = "{0:b}".format(public_n)

    attack_time = 0
    if TIME_ATTACKS:
        attack_time = time.clock() * 1000

    # randomly sample messages between 1 and n
    attack_messages = random.sample(xrange(1, public_n), attacks)


    sqrt_n = math.sqrt(public_n)

    private_key_guess = 0

    # loop through each bit
    for bit in xrange(len(bitwise_n)):
        (m_with_reduction, m_without_reduction) = split_messages(attack_messages, sqrt_n)



    if TIME_ATTACKS:
        attack_time = time.clock() * 1000 - attack_time
        print("Attack took " + str(attack_time) + " ms")

    return timings


def split_messages(messages, cutoff):
    """

    """
    messages_with_reduction = []
    messages_without_reduction = []

    for m in messages:
        if m < cutoff:
            messages_without_reduction.append(m)
        else:
            messages_with_reduction.append(m)

    return (messages_with_reduction, messages_without_reduction)


if __name__ == "__main__":
    rsa = RSAEncryption(961748941, 982451653, 31)


    print(rsa.get_private_keys())
    attack_square_timings = attack_square(rsa, ATTACKS_PER_BIT)
    # print(attack_square_timings)