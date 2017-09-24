#!/usr/bin/env python

import string
import sys

# Build the encoding map
encoding = {}
num = 0b1111111
alphabet = string.ascii_lowercase + string.ascii_uppercase + ' \n' + \
           string.digits + ',./;\[]=-`~!@#$%^&*()_+{}|\\:"?><'
for c in alphabet:
    encoding[num] = c
    num -= 1

def banana_to_int(banana):
    num = ''
    for c in banana:
        if c.isupper():
            num += '1'
        else:
            num += '0'
    return int(num, 2)


def convert_line(line):
    pt = []
    for word in line.split(' '):
        num = banana_to_int(word)
        pt.append(encoding[num])
    return "".join(pt)


if __name__ == "__main__":
    while True:
        text = raw_input("> ")
        try:
            print convert_line(text)
        except:
            print "invalid"
        print
