// -*- coding: utf-8 -*-

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>       // log, pow
#include "mult.h"

#ifndef PolyG
#define PolyG 0x11b     // Le polynôme fixé par l'AES
#endif

typedef unsigned char uchar; 

/* --- On reprend les tables de multiplications construites au premier TD --- */


unsigned int mul_F2X(unsigned int A, unsigned int B){
	unsigned int C=0;
	int i;
	for (i=0; i<32; i++)  
		C ^= (A<<i) * (B>>i & 1);
	return C;
}

int degre(unsigned int A){
	return ((int)(log(A)/log(2)));
}

unsigned int reste_F2X(unsigned int A, unsigned int B){
	if (B == 0) exit(1);
	if (B == 1) return(0);
	while (degre(A)>=degre(B))
		A ^= B<<(degre(A)-degre(B));
	return A;
} 
         
uchar mul_F256(uchar A, uchar B){
	return reste_F2X (mul_F2X(A,B), PolyG);
}

void remplir(){
	int i, j;  
	for(i = 0; i < 256; ++i)
		for(j = 0; j < 256; ++j)
			Mul_F256[i][j] = mul_F256(i,j);
}
/* --- Fin de l'emprunt au premier TD --- */

int longueur_de_la_clef = 16 ;
uchar K[16] = {
  	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
} ;
// La clef utilisée est la clef nulle de longueur 128 bits (16 octets)
  
int longueur_de_la_clef_etendue = 176;
uchar W[176] = { // Résultat du programme du second TD
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
	0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63, 0x62, 0x63, 0x63, 0x63,
	0x9B, 0x98, 0x98, 0xC9, 0xF9, 0xFB, 0xFB, 0xAA, 0x9B, 0x98, 0x98, 0xC9, 0xF9, 0xFB, 0xFB, 0xAA,
	0x90, 0x97, 0x34, 0x50, 0x69, 0x6C, 0xCF, 0xFA, 0xF2, 0xF4, 0x57, 0x33, 0x0B, 0x0F, 0xAC, 0x99,
	0xEE, 0x06, 0xDA, 0x7B, 0x87, 0x6A, 0x15, 0x81, 0x75, 0x9E, 0x42, 0xB2, 0x7E, 0x91, 0xEE, 0x2B,
	0x7F, 0x2E, 0x2B, 0x88, 0xF8, 0x44, 0x3E, 0x09, 0x8D, 0xDA, 0x7C, 0xBB, 0xF3, 0x4B, 0x92, 0x90, 
	0xEC, 0x61, 0x4B, 0x85, 0x14, 0x25, 0x75, 0x8C, 0x99, 0xFF, 0x09, 0x37, 0x6A, 0xB4, 0x9B, 0xA7, 
	0x21, 0x75, 0x17, 0x87, 0x35, 0x50, 0x62, 0x0B, 0xAC, 0xAF, 0x6B, 0x3C, 0xC6, 0x1B, 0xF0, 0x9B, 
	0x0E, 0xF9, 0x03, 0x33, 0x3B, 0xA9, 0x61, 0x38, 0x97, 0x06, 0x0A, 0x04, 0x51, 0x1D, 0xFA, 0x9F, 
	0xB1, 0xD4, 0xD8, 0xE2, 0x8A, 0x7D, 0xB9, 0xDA, 0x1D, 0x7B, 0xB3, 0xDE, 0x4C, 0x66, 0x49, 0x41, 
	0xB4, 0xEF, 0x5B, 0xCB, 0x3E, 0x92, 0xE2, 0x11, 0x23, 0xE9, 0x51, 0xCF, 0x6F, 0x8F, 0x18, 0x8E
};

// 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,

int Nr = 10, Nk = 4;

uchar State[16] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
} ;

void affiche_16_octets(uchar *M) {
	int i;
	for (i=0; i<16; i++) 
		printf ("%02X ", M[i] & 255);
	printf("\n");
}

void affiche_les_clefs_de_ronde(){
	int i,j ;
	for(i=0;i<Nr+1;i++){
		printf("RoundKeys[%02i] = ",i);
		for(j=0;j<16;j++)
			printf(" %02X ", W[i*16 + j]);
		
		printf("\n");
	}
}

void SubBytes(){
	int i;
	for(i=0; i<16; i++){
		State[i] = SBox[State[i]];
	} 
}

void InvSubBytes(){
	int i, j;
	for(i=0; i<16; i++){
		for(j=0; j<256; j++)
			if(SBox[j] == State[i]){
				State[i] = j;
				break;
			}
	} 
}

void ShiftRows()/*essayer d ameliorer*/ {
	uchar tmp;

	tmp = State[1];
	State[1] = State[5];
	State[5] = State[9];
	State[9] = State[13];
	State[13] = tmp;
	
	tmp = State[2];
	State[2] = State[10];
	State[10] = tmp;
	tmp = State[6];
	State[6] = State[14];
	State[14] = tmp;
	
	tmp = State[3];
	State[3] = State[15];
	State[15] = State[11];
	State[11] = State[7];
	State[7] = tmp;
	
}

void InvShiftRows()/*essayer d ameliorer*/ {
	uchar tmp;
	
	tmp = State[13];
	State[13] = State[9];
	State[9] = State[5];
	State[5] = State[1];
	State[1] = tmp;
	
	tmp = State[2];
	State[2] = State[10];
	State[10] = tmp;
	tmp = State[6];
	State[6] = State[14];
	State[14] = tmp;
	
	
	tmp = State[3];
	State[3] = State[7];
	State[7] = State[11];
	State[11] = State[15];
	State[15] = tmp;
	
}

uchar mult[16] = {
  	0x02, 0x01, 0x01, 0x03, 0x03, 0x02, 0x01, 0x01, 0x01, 0x03, 0x02, 0x01, 0x01, 0x01, 0x03, 0x02} ;
  
uchar inv_mult[16] = {
  	0x0E, 0x09, 0x0D, 0x0B, 0x0B, 0x0E, 0x09, 0x0D, 0x0D, 0x0B, 0x0E, 0x09, 0x09, 0x0D, 0x0B, 0x0E} ;
  
void MixColumns(){
	int i, k=0;
	uchar tmp[16];
	
	for(i=0; i<16; i+=4){
		tmp[i] = Mul_F256[State[i]][mult[0]] ^ Mul_F256[State[i+1]][mult[4]] ^ Mul_F256[State[i+2]][mult[k+8]] ^ Mul_F256[State[i+3]][mult[12]];
		tmp[i+1] = Mul_F256[State[i]][mult[1]] ^ Mul_F256[State[i+1]][mult[5]] ^ Mul_F256[State[i+2]][mult[9]] ^ Mul_F256[State[i+3]][mult[13]];
		tmp[i+2] = Mul_F256[State[i]][mult[2]] ^ Mul_F256[State[i+1]][mult[6]] ^ Mul_F256[State[i+2]][mult[10]] ^ Mul_F256[State[i+3]][mult[14]];
		tmp[i+3] = Mul_F256[State[i]][mult[3]] ^ Mul_F256[State[i+1]][mult[7]] ^ Mul_F256[State[i+2]][mult[11]] ^ Mul_F256[State[i+3]][mult[15]]; 	
	}
	
	for(i=0; i<16; i++)
		State[i] = tmp[i];
}

void InvMixColumns(){
	int i, k=0;
	uchar tmp[16];
	
	for(i=0; i<16; i+=4){
		tmp[i] = Mul_F256[State[i]][inv_mult[0]] ^ Mul_F256[State[i+1]][inv_mult[4]] ^ Mul_F256[State[i+2]][inv_mult[k+8]] ^ Mul_F256[State[i+3]][inv_mult[12]];
		tmp[i+1] = Mul_F256[State[i]][inv_mult[1]] ^ Mul_F256[State[i+1]][inv_mult[5]] ^ Mul_F256[State[i+2]][inv_mult[9]] ^ Mul_F256[State[i+3]][inv_mult[13]];
		tmp[i+2] = Mul_F256[State[i]][inv_mult[2]] ^ Mul_F256[State[i+1]][inv_mult[6]] ^ Mul_F256[State[i+2]][inv_mult[10]] ^ Mul_F256[State[i+3]][inv_mult[14]];
		tmp[i+3] = Mul_F256[State[i]][inv_mult[3]] ^ Mul_F256[State[i+1]][inv_mult[7]] ^ Mul_F256[State[i+2]][inv_mult[11]] ^ Mul_F256[State[i+3]][inv_mult[15]]; 	
	}
	
	for(i=0; i<16; i++)
		State[i] = tmp[i]; 
}

void AddRoundKey(int r){
	int i;
	for(i=0; i<16; i++)
		State[i] = State[i] ^ W[r*16+i];
}

void chiffrer(){
	int i;
	AddRoundKey(0);
	for(i = 1; i < Nr; i++) {
		SubBytes();
		ShiftRows();
		MixColumns();
		AddRoundKey(i);
	}
	SubBytes();
	ShiftRows();
	AddRoundKey(Nr);
}

void dechiffrer(){
	int i;
	AddRoundKey(Nr);
	InvShiftRows();
	InvSubBytes();
		
	for(i = Nr-1; i > 0; i--) {
		AddRoundKey(i);
		InvMixColumns();
		InvShiftRows();
		InvSubBytes();
	}
	AddRoundKey(0);
}

int main (int argc, char * argv[]) {

	remplir(); // Nous avons besoin de savoir multiplier des octets pour chiffrer
	printf("La clef utilisée est : \n");
	affiche_16_octets(K);
	printf("Les clefs de rondes sont : \n");
	affiche_les_clefs_de_ronde();
	printf("Le bloc clair est : \n");
	affiche_16_octets(State);
	chiffrer();
	printf("Le bloc chiffré est : \n");
	affiche_16_octets(State);
  
	dechiffrer();
	printf("Le bloc déchiffré est : \n");
	affiche_16_octets(State);
  
  exit(EXIT_SUCCESS);
}

/*
$ make
gcc aes.c -o aes
$ ./aes
La clef utilisée est : 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
Les clefs de rondes sont : 
RoundKeys[00] =  00  00  00  00  00  00  00  00  00  00  00  00  00  00  00  00 
RoundKeys[01] =  62  63  63  63  62  63  63  63  62  63  63  63  62  63  63  63 
RoundKeys[02] =  9B  98  98  C9  F9  FB  FB  AA  9B  98  98  C9  F9  FB  FB  AA 
RoundKeys[03] =  90  97  34  50  69  6C  CF  FA  F2  F4  57  33  0B  0F  AC  99 
RoundKeys[04] =  EE  06  DA  7B  87  6A  15  81  75  9E  42  B2  7E  91  EE  2B 
RoundKeys[05] =  7F  2E  2B  88  F8  44  3E  09  8D  DA  7C  BB  F3  4B  92  90 
RoundKeys[06] =  EC  61  4B  85  14  25  75  8C  99  FF  09  37  6A  B4  9B  A7 
RoundKeys[07] =  21  75  17  87  35  50  62  0B  AC  AF  6B  3C  C6  1B  F0  9B 
RoundKeys[08] =  0E  F9  03  33  3B  A9  61  38  97  06  0A  04  51  1D  FA  9F 
RoundKeys[09] =  B1  D4  D8  E2  8A  7D  B9  DA  1D  7B  B3  DE  4C  66  49  41 
RoundKeys[10] =  B4  EF  5B  CB  3E  92  E2  11  23  E9  51  CF  6F  8F  18  8E 
Le bloc clair est : 
00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 
Le bloc chiffré est : 
66 E9 4B D4 EF 8A 2C 3B 88 4C FA 59 CA 34 2B 2E

*/
