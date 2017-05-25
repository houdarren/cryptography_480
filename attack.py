import math
import copy
import time
import random
import sys

from encryption import *

# time how long attack takes
TIME_ATTACKS = True

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

    for bit in xrange(len(bitwise_n)):
        oracle1_timings = 0
        oracle2_timings = 0

        # randomly sample messages between 1 and n
        attack_messages = random.sample(xrange(1, public_n), attacks)

        for m in attack_messages:
            m_temp = m ** (bit * 2)

            oracle1 = (m_temp * m) ** 2
            oracle2 = (m_temp) ** 2

            oracle1_time = attack_decrypt(rsa, oracle1)
            oracle2_time = attack_decrypt(rsa, oracle2)

            oracle1_timings += oracle1_time
            oracle2_timings += oracle2_time

        timings[bit] = (oracle1_timings, oracle2_timings)

        print(str(bit) + "," + str(timings[bit]))

    if TIME_ATTACKS:
        attack_time = time.clock() * 1000 - attack_time
        print("Attack took " + str(attack_time) + " ms")

    return timings


def _multiply_montgomery(a, b, n_inverse, r, n):
    """Performs modular multiplication using the Montgomery method
    Computes a * b mod n
    """
    t = a * b
    m = t * n_inverse % r
    u = (t + m * n) / r
    if (u >= n):
        return u - n
    return u

def _calculate_n_inverse(n):
    """Calculates r and n-inverse used in Montgomery multiplication,
    returning a tuple consisting of r and n-inverse
    """
    k = int(math.floor(math.log(int(n), 2))) + 1
    r = int(math.pow(2, k))
    r_inverse = _calculate_modular_inverse(r, n)
    result = (r * r_inverse - 1) / n
    return (r, result)

def _calculate_modular_inverse(a, n):
    """Calculates the modular inverse of a mod n"""
    (t, curr_t, r, curr_r) = 0, 1, int(n), int(a)
    while curr_r != 0:
        result = r / curr_r
        (t, curr_t) = (curr_t, t - result * curr_t)
        (r, curr_r) = (curr_r, r - result * curr_r)
    if (t < 0):
        t += n
    return t


if __name__ == "__main__":
    attacks_per_bit = 10000

    rsa = RSAEncryption(961748941, 982451653, 31)

    attack_square_timings = attack_square(rsa, attacks_per_bit)
    # print(attack_square_timings)