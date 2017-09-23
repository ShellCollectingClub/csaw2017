#!/usr/bin/env python

import itertools
import string

from convert import encoding
import disassemble

FLAG_CHARS = string.ascii_letters + string.digits + "_"

banana_ct = "baNANAs banAnAS banANaS banaNAs BANANAs BANaNas BANAnas bANanAS baNaNAs banaNAs bANaNas BaNaNaS baNanas BaNaNas BaNanas BaNANas baNAnaS banaNAS bANAnAs banANAS bAnaNAs BANAnAS BANAnas BaNANas bAnANas BaNaNaS banAnAs bANAnAs baNaNas BanaNaS bANANas banaNas bAnANaS bANANaS BaNAnas baNanAs baNanAS BaNAnAs bANANas banAnas bAnanaS banANaS bANaNAS banANaS baNanAS BaNanAS BANAnAS BaNanaS"

tokens = disassemble.tokenize(banana_ct)
ct = [t.val for t in tokens]

def rolling_xor(ct, key):
    pt = []
    for i, c in enumerate(ct):
        char = c ^ key[i % (len(key))]
        pt.append(char)
    return pt


key = [ 0x64, 0x7f, 0x72, 0x7f, 0x56]
#for i in xrange(256):
#    try:
#        #if encoding[i ^ ct[0]] == 'f':
#        #if encoding[i ^ ct[1]] == 'l':
#        #if encoding[i ^ ct[2]] == 'a':
#        #if encoding[i ^ ct[3]] == 'g':
#        if encoding[i ^ ct[4]] == '{':
#            print hex(i)
#            exit(1)
#    except:
#        pass

for i, seq in enumerate(itertools.product(range(256), repeat=3)):
    guess = key + list(seq)
    pt = rolling_xor(ct, guess)
    try:
        pt = "".join(encoding[c] for c in pt)
        if all(c in string.printable for c in pt) and pt[-1] == "}" and \
           all(c in FLAG_CHARS for c in pt[5:-1]):
            print pt
    except:
        pass
