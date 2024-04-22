from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
import hashlib
import random
import base64
from cryptography import x509
from Crypto.Util.number import bytes_to_long, long_to_bytes

def xor(a, b):
    return [x ^ y for x, y in zip(a, b)]

class MiniFish:
    def hextoint(self, hex):
        return int(hex, 16)

    def __init__(self, key):
        self.key = key
        k_bytes = long_to_bytes(key)
        self.shake = hashlib.shake_256()
        self.shake.update(k_bytes)
        res = self.shake.hexdigest(33344)
        self.round_keys = [None] * 18
        for i in range(0,18):
            self.round_keys[i] = res[i * 8: (i + 1) * 8]
            # print(self.round_keys[i])
            # self.round_keys[i] = bytes_to_long(self.round_keys[i])
            self.round_keys[i] = self.hextoint(self.round_keys[i])
            # print(len(bin(self.round_keys[i])))
        keys_end = 18 * 8
        self.sboxes = [None] * 4
        for i in range(4):
            self.sboxes[i] = [None] * 256
            for j in range(256):
                self.sboxes[i][j] = res[keys_end + i * 256 * 2 + j * 2: keys_end + i * 256 * 2 + j * 2 + 2]
                self.sboxes[i][j] = self.hextoint(self.sboxes[i][j])

    def feistel(self, x):
        print("-----------")
        l = x >> 32 & 0xFFFF
        r = x & 0xFFFF

        for i in range(16):
            l = l ^ self.round_keys[i]
            l1 = l >> 24 & 0xFF
            l2 = (l >> 16) & 0xFF
            l3 = (l >> 8) & 0xFF
            l4 = l & 0xFF

            l1 = self.sboxes[0][l1]
            l2 = self.sboxes[1][l2]
            l3 = self.sboxes[2][l3]
            l4 = self.sboxes[3][l4]
            print(l1, l2, l3, l4)

            tmp = self.feistel_mul(l1, l2) ^ self.feistel_mul(l3, l4)
            # print(len(bin(tmp)) - 2)
            r = r ^ tmp

            (l, r) = (r, l)
        
        (l, r) = (r, l)
        l = l ^ self.round_keys[17]
        r = r ^ self.round_keys[16]

        return (l << 32) | r

    def init_keys(self):
        k_bytes = long_to_bytes(self.key) * 18
        replicated = bytes_to_long(k_bytes)
        bin_len = len(bin(replicated)) - 2

        for i in range(18):
            to_xor = replicated >> (bin_len - 32 * (i + 1)) & 0xFF
            self.round_keys[i] = self.round_keys[i] ^ to_xor

        t = 0

        for i in range(0, 18, 2):
            t = self.feistel(t)
            self.round_keys[i] = t >> 32 & 0xFFFF
            self.round_keys[i + 1] = t & 0xFFFF

        for i in range(0,4):
            for j in range(0,256, 2):
                t = self.feistel(t)
                self.sboxes[i][j] = t >> 32 & 0xFF
                self.sboxes[i][j + 1] = t & 0xFF

    def gf_mul(self, a, b, m):
        p = 0
        while a > 0:
            if a & 1:
                p = p ^ b

            a = a >> 1
            b = b << 1

            if self.deg ( b ) == self.deg ( m ) :
                b = b ^ m
        return p

    def deg(self, x):
        return len(bin(x)) - 3

    def feistel_mul(self, a, b):
        # print(len(bin(a)), len(bin(b)))
        x = self.gf_mul(a,b,340282366920938463463374607431768211591)
        # print(len(bin(x)))
        return x

    def galois_mul(self, a, b):
        return self.gf_mul(a,b,4295000729)

    def encrypt(self, plaintext, aad, iv):
        n = len(bin(plaintext)) - 2
        n = (n + 63) // 64
        ctr = [0] * (n + 1)

        bin_blocks = bin(plaintext)[2:].ljust(64 * n, '0')

        blocks = [bin_blocks[i:i+64] for i in range(0, len(bin_blocks), 64)]
        blocks = [int(block, 2) for block in blocks]
        
        ctr[0] = iv << 4
        y = [0] * (n+1)
        for i in range(1, n + 1):
            ctr[i] = ctr[i - 1] + 1
            y[i] = self.feistel(ctr[i]) ^ blocks[i-1]

        h = self.feistel(0)
        g = self.galois_mul(h, aad)

        for i in range(i, n + 1):
            g = self.galois_mul(g ^ y[i], h)

        tag = self.galois_mul(g, h) ^ self.feistel(ctr[0])

        ciphertext_bytes = [ long_to_bytes(c) for c in y[1:] ]

        return (ciphertext_bytes, tag)


if __name__ == "__main__":
    key = b'klucz'
    iv = b'0123'
    AAD = b'Karol Kasia Oskar'

    text1 = b'matematyka jest super'

    fish = MiniFish(bytes_to_long(key))
    fish.init_keys()
    (cipher, tag) = fish.encrypt(bytes_to_long(text1), bytes_to_long(AAD), bytes_to_long(iv))
    print(cipher)
    print(tag)