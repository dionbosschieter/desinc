//##
//#Dion Bosschieter Super slow implementation of DES,  data encryption standard
//#Compile&run: gcc des.c -o des ; ./des
//##

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void printbits(unsigned long b)
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

void print1bit(unsigned long b)
{
    unsigned long mask = 1L << 0;	
	putchar(b & mask ? '1' : '0');
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
	*newval = (*val << n) | (*val >> 28L - n);
	//mask zodat de laatste bits niet mee worden genomen die geshift zijn
	*newval = *newval & 0xFFFFFFF; 
}

int main()
{
	unsigned long M = 0x123456789ABCDEF;
	unsigned long K = 0x133457799BBCDFF1;
	unsigned long Kp, L, R, C0, D0, Cn[16], Dn[16], Kn[16], CD, IP, E, RL, cypher = 0;
	int i, ii, iii, Ln[17], Rn[17];
	
	printf("M  = ");
	printbits(M);
	
	//split M in L0 en R0
	L = M & 0xFFFFFFFF;
	R = (M >> 32) & 0xFFFFFFFF;

	printf("L0 = ");
	printbits(L);
	printf("R0 = ");
	printbits(R);
	printf("\nK  = ");
	printbits(K);
	
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
	
	
	//permuteren van Key met PC-1
	for(i=0;i<56;i++) {
		if (K & (1L << (64 - PC_1[i]))) { //omdat het omgedraaid wel werkt :S ???
			Kp |= 1L << 55-i;//55-i == 56-i-i dit doe ik om de bits om te draaien
		}
	}
	printf("Kp = ");
	printbits(Kp);
	
	//split permuted key in C0 en D0
	C0 = (Kp >> 28) & 0xFFFFFFF;
	D0 = Kp & 0xFFFFFFF;
	
	printf("C0 = ");
	printbits(C0);
	printf("D0 = ");
	printbits(D0);
	
	unsigned long leftshifts[16] = {1L,1L,2L,2L,2L,2L,2L,2L,1L,2L,2L,2L,2L,2L,2L,1L};
	//voer de leftrotates uit op de Cn^16 en Dn^16
	rotate_right(&C0, leftshifts[0], &Cn[0]);
	rotate_right(&D0, leftshifts[0], &Dn[0]);
	
	printf("C1 = ");
	printbits(Cn[0]);
	printf("D1 = ");
	printbits(Dn[0]);

	for(i=1;i<16;i++) {
		rotate_right(&Cn[i-1], leftshifts[i], &Cn[i]);
		rotate_right(&Dn[i-1], leftshifts[i], &Dn[i]);
		printf("C%i = ", i+1);
		printbits(Cn[i]);
		printf("D%i = ", i+1);
		printbits(Dn[i]);
	}
	
	//maak Kn^16 volgens permutie tabel 2 PC-2
	//CD = ((Cn[0] << 28) | (Dn[0]));
	//printbits(CD);
	
	for(i=0;i<16;i++){
		for(ii=0;ii<48;ii++) {
			if (((Cn[i] << 28) | (Dn[i])) & 1L << (56 - PC_2[ii])) { //omdat het omgedraaid wel werkt :S ???
				Kn[i] |= 1L << 47-ii;//55-i == 56-i-i dit doe ik om de bits om te draaien
			}
		}
		printf("K%i = ", i+1);
		printbits(Kn[i]);
	}
	
	//permutatie van Message
	for(i=0;i<64;i++) {
		if (M & (1L << (64 - IP_C[i]))) { //omdat het omgedraaid wel werkt :S ???
			IP |= 1L << 63-i;//63-i == 64-i-i dit doe ik om de bits om te draaien
		}
	}
	printf("M  = ");
	printbits(M);
	printf("IP = ");
	printbits(IP);
	
	//split IP in 2 32bits integers omdat deze 32 int zijn :) ram houd van ons
	Ln[0] = (IP >> 32) & 0xFFFFFFFF;
	Rn[0] = IP & 0xFFFFFFFF;
	
	printf("L0 = ");
	print32bits(Ln[0]);
	printf("R0 = ");
	print32bits(Rn[0]);
	
	for(i=1;i<17;i++){
		Ln[i] = Rn[i-1];
		E = 0;
		printf("L%i = ", i);
		print32bits(Ln[i]);

		//voer de E_BIT selectie tabel uit om Rn[i] van 32bits naar 48 bits om te zetten
		for(ii=0;ii<48;ii++) {
			if (Rn[i-1] & 1L << (32 - E_BIT[ii])) { //omdat het omgedraaid wel werkt :S ???
				E |= 1L << 47-ii;//48-i == 47-i-i dit doe ik om de bits om te draaien
			}
		}
		
		E ^= Kn[i-1]; //Kn[0] is K1 omdat hij loopt van 0 tot 15
		
		int f1 = 0;
		int f=0;
		
		for(iii = 1; iii < 9; iii++) {  // 8 iteraties omdat er 8 * 6 bits zijn
			//first bit = (iii*6)-6);
			//last bit = (iii*6)-1);

			int tempbitchingfirstrow = E >> (iii*6)-6 & 1L | E >> (iii*6)-2 & 2L;
			int tempbitchingsecondrow = (E >> ((iii*6)-5)) & 0xF;

			f1 |= S[7-(iii-1)][tempbitchingfirstrow][tempbitchingsecondrow] << (4*iii)-4;
		}
		
		//permuteren van f1 met P
		for(iii=0;iii<32;iii++) {
			if (f1 & (1 << (32 - P[iii]))) {
				f |= 1 << 31-iii;
			}
		}
		Rn[i] = Ln[i-1]^f;
		printf("R%i = ", i);
		print32bits(Rn[i]);
	}
	
	//doe berekeningen met Rn[16] en Ln[16];
	RL = Rn[16];
	RL = RL << 32;
	RL |= Ln[16];
	
	printf("R16L16 = ");
	printbits(RL);
	
	for(i=0;i<64;i++) {
		if (RL & (1L << (64 - IP_1[i]))) {
			cypher |= 1L << 63-i;
		}
	}
	printf("IP-1 = ");
	printbits(cypher); 
	printf("Message = %lX\n", M);
	printf("DIT IS IN Cypher text = %lX\n", cypher);
}