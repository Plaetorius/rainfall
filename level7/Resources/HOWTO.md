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

