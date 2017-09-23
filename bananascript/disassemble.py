#!/usr/bin/env python

import argparse
import sys

class Token(object):
    def __init__(self, raw):
        self.raw = raw
        self.val = self._banana_to_int(raw)

    def _banana_to_int(self, banana):
        num = ""              
        for c in banana:      
            if c.isupper():   
                num += "1"    
            else:             
                num += "0"    
        return int(num, 2)    


def tokenize(line):
    tokens = []
    for word in line.split(" "):
        token = Token(word)
        tokens.append(token)
    return tokens

def is_reg(token):
    return token.raw.startswith("banA")

def get_reg(token):
    return token.val & 0x7


def disassemble_line(line, full):
    tokens = tokenize(line)
    if tokens[0].raw == "bananas":
        """Put string"""
        reg = get_reg(tokens[1])
        print "put   r{:d}".format(reg)
        return
    
    if tokens[0].raw == "bananaS":
        """Read an ascii string, encode to banana, and store in reg"""
        reg = get_reg(tokens[1])
        print "get   r{:d}".format(reg)
        return
    
    if tokens[0].raw == "bananAs" and tokens[1].raw == "bananAS":
        """Decode the number in the specified register, and jump forward that many instructions"""
        reg = get_reg(tokens[2])
        print "jmp   a{:d}".format(reg)
        return

    if tokens[0].raw == "bananAS":
        if is_reg(tokens[1]) and tokens[2].raw == "baNanas" and tokens[3].raw != "bananAS":
            """Store to arithmetic register"""
            reg = get_reg(tokens[1])
            string = " ".join(t.raw for t in tokens[3:])
            if not full and len(string) > 60:
                string = string[:60] + "..."
            print "store a{:d}, \"{:s}\"".format(reg, string)
            return


    if tokens[0].raw == "banaNAS":
        reg0 = get_reg(tokens[1])
        reg1 = get_reg(tokens[3])
        if tokens[2].raw == "baNANaS":
            """Skip if greater than or equal. Hash r0 and r1. If r0_hash >= r1_hash: skip line."""
            print "sge   r{:d}, r{:d}".format(reg0, reg1)
            return
        if tokens[2].raw == "baNANAS":
            """Skip if strings are equal"""
            print "se    r{:d}, r{:d}".format(reg0, reg1)
            return
            
    if is_reg(tokens[0]):
        if tokens[1].raw == "baNanas":
            """Store string"""
            reg = get_reg(tokens[0])
            string = " ".join(t.raw for t in tokens[2:])
            if not full and len(string) > 60:
                string = string[:60] + "..."
            print "store r{:d}, \"{:s}\"".format(reg, string)
            return

        if tokens[1].raw == "baNAnas":  # OP1
            """Mix the strings (see op1.py for impl details)"""
            reg0 = get_reg(tokens[0])
            reg1 = get_reg(tokens[2])
            print "mix   r{:d}, r{:d}".format(reg0, reg1)
            return

        if tokens[1].raw == "baNaNas":  # OP3
            """String Or"""
            reg0 = get_reg(tokens[0])
            reg1 = get_reg(tokens[2])
            print "or    r{:d}, r{:d}".format(reg0, reg1)
            return
    
        if tokens[1].raw == "baNanAS":  # OP4
            """XOR - If equal then drop to lower, else upper."""
            reg0 = get_reg(tokens[0])
            reg1 = get_reg(tokens[2])
            print "xor   r{:d}, r{:d}".format(reg0, reg1)
            return

    print line


def disassemble(filename, full):
    with open(filename, "r") as f:
        lines = f.readlines()

    i = 0;
    for line in lines:
        line = line.strip()
        if line:
            sys.stdout.write("{:2x}: ".format(i))
            disassemble_line(line, full)
            i += 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("script")
    parser.add_argument("-f", "--full", action="store_true",
                        help="Print full banana strings")

    args = parser.parse_args()
    disassemble(args.script, args.full)
