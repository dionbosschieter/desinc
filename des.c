/**
 * Dion Bosschieter implementation of DES,  data encryption standard
 * Compile&run: gcc -Wall des.c -o des ; ./des
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void print64bits(unsigned long b)
{
    int i;
    int s = 8 * (sizeof b) - 1;

    for (i = s; i >= 0; i--)
    {
        unsigned long mask = 1L << i;
        putchar(b & mask ? '1' : '0');
    }
    putchar('\n');
}

void print32bits(int b)
{
    int i;
    int s = 8 * (sizeof b) - 1;

    for (i = s; i >= 0; i--)
    {
        int mask = 1 << i;
        putchar(b & mask ? '1' : '0');
    }
    putchar('\n');
}

void rotate_right(unsigned long* val, unsigned long n, unsigned long* newval)
{
    //shift bits zodat je naar links shift of naar rechts shift met 28 bits
    // zodat het aan het begin er bij word geplakt
    *newval = (*val << n) | (*val >> (28L - n));
    //mask zodat de laatste bits niet mee worden genomen die geshift zijn
    *newval = *newval & 0xFFFFFFF;
}

void permute(unsigned long* input, unsigned long* output, int* permutationTable, int tablelength, int bitlength)
{
    int i;
    *output = 0L;

    for(i=0;i<tablelength;i++) {
        if (*input & (1L << (bitlength - permutationTable[i]))) {
            *output |= 1L << ((tablelength-1)-i);
        }
    }
}

void permuteIntToLong(int* input, unsigned long* output, int* permutationTable, int tablelength)
{
    int i;
    *output = 0L;

    for(i=0;i<tablelength;i++) {
        if (*input & (1L << (32 - permutationTable[i]))) {
            *output |= 1L << ((tablelength-1)-i);
        }
    }
}

void permuteInt(int* input, int* output, int* permutationTable)
{
    int i;
    *output = 0L;

    for(i=0;i<32;i++) {
        if (*input & (1L << (32 - permutationTable[i]))) {
            *output |= 1L << ((32-1)-i);
        }
    }
}

//defineren van permutatie tabellen
int PC_1[56] = {
    57,   49,    41,   33,    25,    17,    9,
     1,   58,    50,   42,    34,    26,   18,
    10,    2,    59,   51,    43,    35,   27,
    19,   11,     3,   60,    52,    44,   36,
    63,   55,    47,   39,    31,    23,   15,
     7,   62,    54,   46,    38,    30,   22,
    14,    6,    61,   53,    45,    37,   29,
    21,   13,     5,   28,    20,    12,    4};

int PC_2[48] = {
    14,    17,   11,    24,     1,    5,
     3,    28,   15,     6,    21,   10,
    23,    19,   12,     4,    26,    8,
    16,     7,   27,    20,    13,    2,
    41,    52,   31,    37,    47,   55,
    30,    40,   51,    45,    33,   48,
    44,    49,   39,    56,    34,   53,
    46,    42,   50,    36,    29,   32};

int IP_C[64] = {
    58,    50,   42,    34,    26,   18,    10,    2,
    60,    52,   44,    36,    28,   20,    12,    4,
    62,    54,   46,    38,    30,   22,    14,    6,
    64,    56,   48,    40,    32,   24,    16,    8,
    57,    49,   41,    33,    25,   17,     9,    1,
    59,    51,   43,    35,    27,   19,    11,    3,
    61,    53,   45,    37,    29,   21,    13,    5,
    63,    55,   47,    39,    31,   23,    15,    7};

int E_BIT[48] = {
    32,     1,    2,     3,     4,    5,
     4,     5,    6,     7,     8,    9,
     8,     9,   10,    11,    12,   13,
    12,    13,   14,    15,    16,   17,
    16,    17,   18,    19,    20,   21,
    20,    21,   22,    23,    24,   25,
    24,    25,   26,    27,    28,   29,
    28,    29,   30,    31,    32,    1};

int S[8][4][16] =
    {{{14,  4, 13,  1,  2,  15,  11,  8,  3,  10,  6,  12,  5,  9,   0,  7},
    { 0, 15,  7,  4,  14,  2,  13,  1,  10,  6,  12, 11,  9,  5,   3,  8},
    { 4,  1, 14,  8,  13,  6,   2, 11,  15, 12,   9,  7,  3, 10,   5,  0},
    {15, 12,  8,  2,   4,  9,   1,  7,   5, 11,   3, 14, 10,  0,   6, 13}},

    {{ 15,  1,  8, 14,  6, 11,   3,  4,   9,  7,   2, 13,  12,  0,  5, 10},
    {  3, 13,  4,  7, 15,  2,   8, 14,  12,  0,   1, 10,   6,  9, 11,  5},
    {  0, 14,  7, 11, 10,  4,  13,  1,   5,  8,  12,  6,   9,  3,  2, 15},
    { 13,  8, 10,  1,  3, 15,   4,  2,  11,  6,   7, 12,   0,  5, 14,  9}},

    {{ 10,  0,  9, 14,   6,  3, 15,  5,  1, 13,  12,  7,  11,  4,   2,  8},
    { 13,  7,  0,  9,   3,  4,  6, 10,  2,  8,   5, 14,  12, 11,  15,  1},
    { 13,  6,  4,  9,   8, 15,  3,  0, 11,  1,   2, 12,   5, 10,  14,  7},
    {  1, 10, 13,  0,   6,  9,  8,  7,  4, 15,  14,  3,  11,  5,   2, 12}},

    {{  7, 13,  14, 3,   0,  6,   9, 10,  1,  2,  8,  5,  11, 12,   4, 15},
    { 13,  8,  11, 5,   6, 15,   0,  3,  4,  7,  2, 12,   1, 10,  14,  9},
    { 10,  6,   9, 0,  12, 11,   7, 13, 15,  1,  3, 14,   5,  2,   8,  4},
    {  3, 15,   0, 6,  10,  1,  13,  8,  9,  4,  5, 11,  12,  7,   2, 14}},

    {{  2, 12,  4,  1,   7, 10,  11,  6,   8,  5,   3, 15, 13,  0, 14,  9},
    { 14, 11,  2, 12,   4,  7,  13,  1,   5,  0,  15, 10,  3,  9,  8,  6},
    {  4,  2,  1, 11,  10, 13,   7,  8,  15,  9,  12,  5,  6,  3,  0, 14},
    { 11,  8, 12,  7,   1, 14,   2, 13,   6, 15,   0,  9, 10,  4,  5,  3}},

    {{ 12,  1, 10, 15,   9,  2,   6,  8,   0, 13,   3,  4, 14,  7,  5, 11},
    { 10, 15,  4,  2,   7, 12,   9,  5,   6,  1,  13, 14,  0, 11,  3,  8},
    {  9, 14, 15,  5,   2,  8,  12,  3,   7,  0,   4, 10,  1, 13, 11,  6},
    {  4,  3,  2, 12,   9,  5,  15, 10,  11, 14,   1,  7,  6,  0,  8, 13}},

    {{  4, 11,  2, 14,  15,  0,   8, 13,   3, 12,   9,  7,  5, 10,  6,  1},
    { 13,  0, 11,  7,   4,  9,   1, 10,  14,  3,   5, 12,  2, 15,  8,  6},
    {  1,  4, 11, 13,  12,  3,   7, 14,  10, 15,   6,  8,  0,  5,  9,  2},
    {  6, 11, 13,  8,   1,  4,  10,  7,   9,  5,   0, 15, 14,  2,  3, 12}},

    {{ 13,  2,  8,  4,   6, 15,  11,  1,  10,  9,   3, 14,  5,  0, 12,  7},
    {  1, 15, 13,  8,  10,  3,   7,  4,  12,  5,   6, 11,  0, 14,  9,  2},
    {  7, 11,  4,  1,   9, 12,  14,  2,   0,  6,  10, 13, 15,  3,  5,  8},
    {  2,  1, 14,  7,   4, 10,   8, 13,  15, 12,   9,  0,  3,  5,  6, 11}}};

int P[32] = {
     16,   7,  20,  21,
     29,  12,  28,  17,
      1,  15,  23,  26,
      5,  18,  31,  10,
      2,   8,  24,  14,
     32,  27,   3,   9,
     19,  13,  30,   6,
     22,  11,   4,  25};


int IP_1[64] = {
    40,     8,   48,    16,    56,   24,    64,   32,
    39,     7,   47,    15,    55,   23,    63,   31,
    38,     6,   46,    14,    54,   22,    62,   30,
    37,     5,   45,    13,    53,   21,    61,   29,
    36,     4,   44,    12,    52,   20,    60,   28,
    35,     3,   43,    11,    51,   19,    59,   27,
    34,     2,   42,    10,    50,   18,    58,   26,
    33,     1,   41,     9,    49,   17,    57,   25};

unsigned long Des(unsigned long M, unsigned long K, int decrypt)
{
    unsigned long Kp, C0, D0, Cn[16], Dn[16];
    unsigned long CD, Kn[16], IP, E, RL, cypher = 0;

    int i, j, Ln[17], Rn[17];

    //permuteren van Key met PC-1
    permute(&K, &Kp, PC_1, 56, 64);

    //split permuted key in C0 en D0
    C0 = (Kp >> 28) & 0xFFFFFFF;
    D0 = Kp & 0xFFFFFFF;

    unsigned long leftshifts[16] = {1L,1L,2L,2L,2L,2L,2L,2L,1L,2L,2L,2L,2L,2L,2L,1L};

    //voer de leftrotates uit op de Cn^16 en Dn^16
    rotate_right(&C0, leftshifts[0], &Cn[0]); //C1
    rotate_right(&D0, leftshifts[0], &Dn[0]); //D1


    for(i=1;i<16;i++) {
        rotate_right(&Cn[i-1], leftshifts[i], &Cn[i]);
        rotate_right(&Dn[i-1], leftshifts[i], &Dn[i]);
    }

    //maak Kn^16 volgens permutie tabel 2 PC-2
    for(i=0;i<16;i++) {
        //C1+C2
        CD = ((Cn[i] << 28) | (Dn[i]));
        permute(&CD, &Kn[i], PC_2, 48, 56);
    }

    //permutatu Message with IP_C
    //creates IP
    permute(&M, &IP, IP_C, 64, 64);

    //split IP in 2 32bits integers
    Ln[0] = (IP >> 32) & 0xFFFFFFFF;
    Rn[0] = IP & 0xFFFFFFFF;

    for(i=1;i<17;i++){
        Ln[i] = Rn[i-1];

        //permute with E_BIT table to make 48bits of the 32bits Rn[i-1]
        permuteIntToLong(&Rn[i-1], &E, E_BIT, 48);

        //Xor E with key Kn
        if(decrypt == 0) {
            E ^= Kn[i-1];
        } else if(decrypt == 1) {
            E ^= Kn[16-i];
        }

        int f1 = 0;

        for(j = 1; j < 9; j++) {  // 8 iteraties omdat er 8 * 6 bits zijn
            //first bit = (j*6)-6);
            //last bit = (j*6)-1);

            int firstrow  = ((E >> ((j*6)-6)) & 1L) | ((E >> ((j*6)-2)) & 2L);
            int secondrow = (E >> (((j*6)-5)) & 0xF);

            f1 |= S[7-(j-1)][firstrow][secondrow] << ((4*j)-4);
        }

        //permute f1 with P
        int f = 0;
        permuteInt(&f1, &f, P);

        //XOR L[i-1] with
        Rn[i] = Ln[i-1]^f;
    }

    //Compute RL with Rn[16] and Ln[16];
    RL = Rn[16];
    RL = (RL << 32);
    RL |= (0x00000000FFFFFFFF & Ln[16]);

    //Permute RL with permutation table IP_1
    permute(&RL, &cypher, IP_1,64,64);

    return cypher;
}

void printchar(char b[])
{
    int i;
    int s = 8 * (sizeof b[0]) - 1;

    for (i = s; i >= 0; i--)
    {
        int mask = 1 << i;
        putchar(b[0] & mask ? '1' : '0');
    }
    putchar('\n');
}

int main()
{
    unsigned long message = 0x0123456789ABCDEF;
    unsigned long key = 0x133457799BBCDFF1;
    unsigned long cyphertext, decrypted;

    printf("Message = %lX\n", message);
    printf("Key = %lX\n", key);

    cyphertext = Des(message, key, 0);
    printf("Encrypted cyphertext = %lX\n", cyphertext);

    decrypted = Des(cyphertext, key, 1);
    printf("Decrypted text = %lX\n", decrypted);

    return 0;
}
