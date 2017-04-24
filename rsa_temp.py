import math
import copy

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
        return (self.e, self.n)

    def get_private_keys(self):
        return (self.p, self.q, self.d)

    def _calculate_modular_inverse(self, a, n):
        """Calculates the modular inverse of a mod n"""
        (t, new_t, r, new_r) = 0, 1, int(n), int(a)
        while new_r != 0:
            quotient = r / new_r
            (t, new_t) = (new_t, t - quotient * new_t)
            (r, new_r) = (new_r, r - quotient * new_r)
        if t < 0:
            t += n
        return t

    def _multiply_montgomery(self, a, b, n_inverse, r):
        """Performs modular multiplication using the Montgomery method."""
        n = self.n

        t = a * b
        m = t * n_inverse % r
        u = (t + m * n) / r
        if (u >= n):
            return u - n
        return u

    def _calculate_n_inverse(self):
        """Calculates r and n-inverse used in Montgomery exponentiation.
        Returns a tuple consisting of r and n-inverse.
        """
        n = self.n

        k = int(math.floor(math.log(int(n), 2))) + 1
        r = int(math.pow(2, k))
        r_inverse = self._calculate_modular_inverse(r, n)
        result = (r * r_inverse - 1) / n
        return (r, result)

    def _convert_integer_to_bit_string(self):
        n = self.n

        bits = []
        k = int(math.floor(math.log(n, 2))) + 1
        for i in list(reversed(list(xrange(k)))):
            # right shift by i and keep only the LSB
            bits.append(n >> i & 1)
        return bits

    def _square_and_multiply(self, m):
        """Exponentiates using square-and-multiply"""
        d = self.d
        n = self.n

        (r, n_prime) = self._calculate_n_inverse()
        m_bar = (m * r) % n
        x_bar = 1 * r % n
        bit_list = self._convert_integer_to_bit_string()
        for bit in bit_list:
            x_bar = self._multiply_montgomery(x_bar, x_bar, n_prime, r)
            if bit == 1:
                x_bar = self._multiply_montgomery(m_bar, x_bar, n_prime, r)
        x = self._multiply_montgomery(x_bar, 1, n_prime, r)
        return x

    def _convert_string_to_ascii(self, m):
        """Converts a string m to a list of ASCII values"""
        return [ord(c) for c in m]

    def _convert_ascii_to_string(self, l):
        """Converts a list of integers to a string based on ASCII
        values
        """
        return ''.join(map(chr, filter(lambda c: c != 0, l)))

    def _convert_integers_to_blocks(self, l):
        """Converts a list of ints l to block size n. Pads l if size is
        insufficient.
        """
        block_size = self.block_size

        result = []
        int_list = copy.copy(l)
        if len(int_list) % block_size != 0:
            for i in xrange(block_size - len(int_list) % block_size):
                int_list.append(0)
        for i in xrange(0, len(int_list), block_size):
            block = 0
            for j in xrange(block_size):
                # shift to correct place
                block += int_list[i + j] << (8 * (block_size - j - 1))
            result.append(block)
        return result

    def _convert_block_to_integers(self, blocks):
        """Converts a list of blocks to ints"""
        block_size = self.block_size

        block_list = copy.copy(blocks)
        result = []
        for block in block_list:
            inner = []
            for i in xrange(self.block_size):
                inner.append(block % 256)
                block = block >> 8
            inner.reverse()
            result.extend(inner)
        return result

    def encrypt(self, message):
        """Encrypts a message using the public key, and returns the
        cyphertext
        """
        e = self.e
        n = self.n

        number_list = self._convert_string_to_ascii(message)
        blocks = self._convert_integers_to_blocks(number_list)
        result = [self._square_and_multiply(block) for block in blocks]
        print(result)
        return result

    def decrypt(self, ciphertext):
        """ Decrypts a ciphertext using the private key, and returns the
        original message
        """
        d = self.d
        n = self.n

        blocks = [self._square_and_multiply(block) for block in ciphertext]
        #print(blocks)
        number_list = self._convert_block_to_integers(blocks)
        #print(number_list)
        result = self._convert_ascii_to_string(number_list)
        return result


if __name__ == "__main__":
    rsa = RSAEncryption(961748941, 982451653, 31)

    # public_keys = rsa.get_public_keys()
    # private_keys = rsa.get_private_keys()
    # print("p: " + str(private_keys[0]))
    # print("q: " + str(private_keys[1]))
    # print("n: " + str(public_keys[1]))
    # print("e: " + str(public_keys[0]))
    # print("d: " + str(private_keys[2]))

    message = "Hello, world! This is Darren and Judy and Christina."
    ciphertext = rsa.encrypt(message)
    decoded_message = rsa.decrypt(ciphertext)

    # print("Message: " + message)
    # print("Ciphertext: " + str(ciphertext))
    # print("Decrypted: " + decoded_message)
