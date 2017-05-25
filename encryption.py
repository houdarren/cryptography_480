import math
import copy
import sys

class RSAEncryption:

    def __init__(self, p, q, e):
        self.p = p  # private key p
        self.q = q  # private key q
        self.e = e  # public key e
        self.n = p * q  # public key N
        self.totient = (p - 1) * (q - 1)  # Euler's totient
        self.d = self._calculate_modular_inverse(e, self.totient)  # private key d
        self.block_size = 2

    def get_public_keys(self):
        """Returns a tuple of the public keys e, N"""
        return (self.n, self.e)

    def get_private_keys(self):
        """Returns a tuple of the private keys p, q, d"""
        return (self.p, self.q, self.d)

    def _calculate_modular_inverse(self, a, n):
        """Calculates the modular inverse of a mod n"""
        (t, curr_t, r, curr_r) = 0, 1, int(n), int(a)
        while curr_r != 0:
            result = r / curr_r
            (t, curr_t) = (curr_t, t - result * curr_t)
            (r, curr_r) = (curr_r, r - result * curr_r)
        if (t < 0):
            t += n
        return t

    def _multiply_montgomery(self, a, b, n_inverse, r):
        """Performs modular multiplication using the Montgomery method
        Computes a * b mod n
        """
        t = a * b
        m = t * n_inverse % r
        u = (t + m * self.n) / r
        while (u >= self.n):
            u = u - self.n
        return u

    def _calculate_n_inverse(self):
        """Calculates r and n-inverse used in Montgomery multiplication,
        returning a tuple consisting of r and n-inverse
        """
        k = int(math.floor(math.log(int(self.n), 2))) + 1
        r = int(math.pow(2, k))
        r_inverse = self._calculate_modular_inverse(r, self.n)
        result = (r * r_inverse - 1) / self.n
        return (r, result)

    def _convert_integer_to_bits(self, key):
        bit_string = []
        k = int(math.floor(math.log(key, 2))) + 1
        for i in list(reversed(list(xrange(k)))):
            # right shift by i and keep only the LSB
            bit_string.append(key >> i & 1)
        return bit_string

    def _square_and_multiply(self, m, key):
        """Exponentiates using square-and-multiply"""
        (r, n_prime) = self._calculate_n_inverse()
        m_bar = (m * r) % self.n
        x_bar = 1 * r % self.n

        bit_list = self._convert_integer_to_bits(key)
        for bit in bit_list:
            x_bar = self._multiply_montgomery(x_bar, x_bar, n_prime, r)
            # perform Montgomery multiplication again to remove bit
            # exploited by a timing attack
            if bit == 1:
                x_bar = self._multiply_montgomery(m_bar, x_bar, n_prime, r)
        x_bar = self._multiply_montgomery(x_bar, 1, n_prime, r)
        return x_bar

    def _convert_string_to_ascii(self, m):
        """Converts a string m to a list of ASCII values"""
        return [ord(c) for c in m]

    def _convert_ascii_to_string(self, integers):
        """Converts a list of integers to a string based on ASCII
        values
        """
        return ''.join(map(chr, filter(lambda c: c != 0, integers)))

    def _convert_integers_to_blocks(self, integers):
        """Converts a list of ints to block size n. Pads the list if size is
        insufficient.
        """
        block_size = self.block_size

        result = []
        int_list = copy.copy(integers)

        # check if int_list needs padding to reach a multiple of block_size
        if len(int_list) % block_size != 0:
            for i in xrange(block_size - len(int_list) % block_size):
                int_list.append(0)

        # convert to blocks
        for i in xrange(0, len(int_list), block_size):
            block = 0
            for j in xrange(block_size):
                # shift to correct place
                block += int_list[i + j] << (8 * (block_size - j - 1))
            result.append(block)

        return result

    def _convert_blocks_to_integers(self, blocks):
        """Converts a list of blocks to ints using the set
        block_size
        """
        block_size = self.block_size

        block_list = copy.copy(blocks)
        result = []
        for block in block_list:
            temp = []  # blocks to add on to final int list
            for i in xrange(self.block_size):
                temp.append(block % 256)
                block = block >> 8
            temp.reverse()
            result.extend(temp)
        return result

    def encrypt(self, message):
        """Encrypts a message using the public key, and returns the
        ciphertext
        """
        number_list = self._convert_string_to_ascii(message)
        blocks = self._convert_integers_to_blocks(number_list)
        result = [self._square_and_multiply(block, self.e) for block in blocks]
        return result

    def decrypt(self, ciphertext):
        """ Decrypts a ciphertext using the private key, and returns the
        original message
        """
        blocks = [self._square_and_multiply(block, self.d) for block in ciphertext]
        number_list = self._convert_blocks_to_integers(blocks)
        result = self._convert_ascii_to_string(number_list)
        return result
