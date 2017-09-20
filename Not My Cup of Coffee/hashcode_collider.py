import itertools

good = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890'

def java_string_hashcode(s):
   h = 0
   for c in s:
       h = (31 * h + ord(c)) & 0xFFFFFFFF
   return ((h + 0x80000000) & 0xFFFFFFFF) - 0x80000000


def iter_city(target):
    target_code = java_string_hashcode(target)
    for x in itertools.combinations(good, r=3):
        if java_string_hashcode(''.join(x)) == target_code:
            return x


def find_bads(s):
    x = []
    for i, ch in enumerate(s):
        if ch not in good:
            x.append(i)
    return x


if __name__ == "__main__":
    target = 'Flag'
    win = list(target)
    bads = find_bads(target)
    for x in bads:
        a,b,c = iter_city(target[x-1] + target[x] + target[x+1])
        win[x-1] = a
        win[x] = b
        win[x+1] = c
    print ''.join(win)