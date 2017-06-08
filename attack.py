import math
import copy
import time
import random
import sys

from encryption import *

# time how long total attack takes
TIME_ATTACKS = False

ATTACKS_PER_BIT = 8000

PRIVATE_D = 0



def attack_decrypt(rsa, message):
    start_time = time.clock() * 1000
    rsa.decrypt([message])
    end_time = time.clock() * 1000

    return end_time - start_time


def time_messages(rsa, message_sets):
    timings = []

    for message_set in message_sets:
        if len(message_set) > ATTACKS_PER_BIT:
            message_set = message_set[:ATTACKS_PER_BIT]

        # scale up size of message set if needed
        if len(message_set) < ATTACKS_PER_BIT / 3:
            scale = ATTACKS_PER_BIT / len(message_set)
            message_set = [message_set[i / scale] for i in range(len(message_set) * scale)]

        set_timing = 0
        for message in message_set:
            set_timing += attack_decrypt(rsa, message)

        # check message set not empty
        if len(message_set) <= 0:
            print("message_set is empty")
            timings.append(0)
        else:
            timings.append(set_timing / len(message_set))

    return timings



def attack_square(rsa, attacks, bit_sequence):
    """Attacks the square portion of the square-and-multiply
    algorithm
    """
    bits_incorrect = 0
    bits_attacked = 0

    (public_n, public_e) = rsa.get_public_keys()
    bitwise_n = to_bit_string(public_n)

    # time length of attack
    attack_time = 0
    if TIME_ATTACKS:
        attack_time = time.clock() * 1000

    # randomly choose messages between 1 and n
    attack_messages = random.sample(xrange(1, public_n), attacks / 2)
    # loop through each bit
    for i in xrange(1, len(bitwise_n)):
        reduction_messages = build_reduction_messages(attacks / 2, bit_sequence, public_n)
        attack_messages = attack_messages + reduction_messages

        message_sets = split_messages(attack_messages, bit_sequence, math.sqrt(public_n), public_n)

        timings = time_messages(rsa, message_sets)

        bit_guess = guess_bit(timings)

        if not verify_bit(bit_guess, i):
            bit_guess = 1 - bit_guess
            bits_incorrect += 1
            print("GUESS WRONG")
        else:
            print("GUESS RIGHT")

        bit_sequence = build_bit_sequence(bit_guess, i, bit_sequence)

        bits_attacked += 1

        print(to_bit_string(bit_sequence))

    # time length of attack
    if TIME_ATTACKS:
        attack_time = time.clock() * 1000 - attack_time
        print("Attack took " + str(attack_time) + " ms")

    return bit_sequence


def split_messages(messages, bit_sequence_guess, cutoff, public_n):
    """

    """
    r_1 = []
    n_1 = []
    r_0 = []
    n_0 = []

    for m in messages:
        m_temp = m ** (bit_sequence_guess) % public_n

        # first oracle
        if over_cutoff(((m_temp * m) ** 2), cutoff):
            r_1.append(m_temp)
        else:
            n_1.append(m_temp)

        # second oracle
        if over_cutoff((m_temp ** 2), cutoff):
            r_0.append(m_temp)
        else:
            n_0.append(m_temp)

    oracles = [r_1, n_1, r_0, n_0]

    for oracle in oracles:
        if len(oracle) > ATTACKS_PER_BIT:
            oracle = oracle[:ATTACKS_PER_BIT]

    return oracles


def over_cutoff(n, cutoff):
    return n >= cutoff


def build_bit_sequence(bit_guess, index, sequence):
    return 2 ** index * bit_guess + sequence


def verify_bit(bit_guess, index):
    d = to_bit_string(PRIVATE_D)
    return d[len(d) - 1 - index] == str(bit_guess)


def guess_bit(timings):
    print(timings)
    oracle1_difference = timings[0] - timings[1]
    oracle2_difference = timings[2] - timings[3]

    if oracle1_difference > oracle2_difference:
        return 1
    else:
        return 0


def to_bit_string(n):
    return "{0:b}".format(n)


def build_reduction_messages(attacks, bit_sequence_guess, public_n):
    """Returns a list of messages needing an extra reduction step"""
    attacks = min(attacks, 2 ** bit_sequence_guess - 1)
    messages = random.sample(xrange(1, 2 ** (bit_sequence_guess) % public_n), attacks)
    m = []
    for message in messages:
        m_temp = message ** (bit_sequence_guess) % public_n
        m.append(m_temp)
    return m


if __name__ == "__main__":
    rsa = RSAEncryption(97007, 98179, 31)
    (p, q, d) = rsa.get_private_keys()

    PRIVATE_D = d
    print(to_bit_string(d))

    # private key guess, with first bit given
    bit_sequence = 1

    print(rsa.get_private_keys())
    attack_square_timings = attack_square(rsa, ATTACKS_PER_BIT, bit_sequence)
    # print(attack_square_timings)