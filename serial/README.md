# Serial
## 50 points
## Misc

This challenge was a pretty straight forward serial data transmission. The
structure of the messages appear to be:

```
bit[0]      header bit, always 0
bit[1-8]    data
bit[9]      parity bit
bit[10]     stop bit, always 1
```

The [parity bit](https://en.wikipedia.org/wiki/Parity_bit) is calculated by essentially counting the number of high bits. If the 
number of high bits is even, the parity bit should be 1, and if it is odd the 
parity bit should be 0. 

When connecting to the challenge service, it prompts you with:

`8-1-1 even parity. Respond with '1' if you got the byte, '0' to retransmit.`

So, we find the number of number of high bits in the 8 bits after the header
bit, mod it by 2, and see if the parity bit is equal to the result. If it is,
we append the character representation of that byte to our flag. Once we
receive all of the bytes, we win.

See our [script](serial_solve.py).
