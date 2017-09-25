#!/usr/bin/env python

import string
import z3

import almostxor

ct = "809fdd88dafa96e3ee60c8f179f2d88990ef4fe3e252ccf462deae51872673dcd34cc9f55380cb86951b8be3d8429839"
ct = ct.decode('hex')

def solve(n, keylen):
    mlen = len(ct)
    total = mlen * 8
    nytes = total // n

    s = z3.Solver()

    pt = z3.BitVec("pt", total)
    key = z3.BitVec("key", total)
    cipher = z3.BitVec("ct", total)

    def nyte(bitvec, n, i):
        """Extract the i'th n-bit value from bitvec."""
        start = bitvec.size() - n - (i * n)
        return z3.Extract(start+n-1, start, bitvec)

    # Plaintext is ascii
    for i in xrange(mlen):
        s.add(nyte(pt, 8, i) >= 0x20)
        s.add(nyte(pt, 8, i) <= 0x7e)

    # Plaintext starts with "flag{" and ends with "}"
    for i, c in enumerate("flag{"):
        s.add(nyte(pt, 8, i) == ord(c))
    s.add(nyte(pt, 8, mlen-1) == ord("}"))

    # Key is repeating
    for i in xrange(keylen, mlen):
        s.add(nyte(key, 8, i) == nyte(key, 8, i % keylen))

    # Known ciphertext
    for i, c in enumerate(ct):
        s.add(nyte(cipher, 8, i) == ord(c))

    # Transformation
    for i in xrange(nytes):
        m = nyte(pt, n, i)
        k = nyte(key, n, i)
        c = nyte(cipher, n, i)
        s.add(c == (m + k) & ((1 << n) - 1))

    cnt = 0
    while z3.sat == s.check():
        if cnt > 5:
            return
        cnt += 1
        plaintext = s.model()[pt].as_long()
        flag = hex(plaintext)[2:-1].decode("hex")
        print "[*] {:s}".format(flag)
        s.add(pt != plaintext)


# Try to solve for all block sizes
for n in xrange(2, 8):
    # Ciphertext length must be a multiple of blocksize
    if len(ct) % n != 0:
        continue

    # Try to solve for all key lengths
    for keylen in xrange(2, len(ct)):
        print n, keylen
        solve(n, keylen)

