from pwn import *
import socket

def check_parity(data, parity):
    n = sum([x == '1' for x in data])
    if n % 2 == parity:
        return (data, '1')
    else:
        return ('', '0')


def get_flag():
    chal = remote('misc.chal.csaw.io', 4239)
    flag = ''
    data = chal.recv().split('\n')[1]
    while True:
        check_data = data[1:9]
        parity = int(data[9])
        flag_byte, to_send = check_parity(check_data.strip(), parity)
        if len(flag_byte) > 0:
            flag += chr(int(flag_byte,2))
            if flag[-1] == '}':
                return flag
        chal.sendline(to_send)
        data = chal.recv().strip()


if __name__ == "__main__":
    print get_flag()