/*
blowfish.h:  Header file for blowfish.c

Copyright (C) 1997 by Paul Kocher

This library is free software; you can redistribute it and/or
modify it under the terms of the GNU Lesser General Public
License as published by the Free Software Foundation; either
version 2.1 of the License, or (at your option) any later version.
This library is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
Lesser General Public License for more details.
You should have received a copy of the GNU Lesser General Public
License along with this library; if not, write to the Free Software
Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA


See blowfish.c for more information about this file.
*/

#include <stdio.h>
#include <stdint.h>

/*
 * This file has been modified by the Wireless Innovation and Cybersecurity Lab of George Mason University
 * This project was overseen by Dr. Kai Zeng from the Department of Electrical and Computer Engineering
 * Contributing Members: David Rudo, Brandon Fogg, Thomas Lu, Matthew Chang, Yaqi He, Shrinath Iyer
 */

typedef struct {
	uint32_t P[16 + 2];
	uint32_t S[4][256];
} BLOWFISH_CTX;

void Blowfish_Init(BLOWFISH_CTX* ctx, uint8_t* key, int32_t keyLen);
void Encrypt(BLOWFISH_CTX* ctx, uint8_t* x);
void Decrypt(BLOWFISH_CTX* ctx, uint8_t* x);
void Blowfish_Encrypt(BLOWFISH_CTX* ctx, uint32_t* xl, uint32_t* xr);
void Blowfish_Decrypt(BLOWFISH_CTX* ctx, uint32_t* xl, uint32_t* xr);



