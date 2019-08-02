/*
* This file has been modified by the Wireless Innovation and Cybersecurity Lab of George Mason University
* This project was overseen by Dr. Kai Zeng from the Department of Electrical and Computer Engineering
* Contributing Members: David Rudo, Brandon Fogg, Thomas Lu, Matthew Chang, Yaqi He, Shrinath Iyer
*/

#include <stdint.h>
#include <stdio.h>

#define XTDELTA		0x9e3779b9u
#define XTROUND		32
#define XTSUM		0xc6ef3720u

void XTeaEncrypt(/*uint32_t* w, */void* v, const uint32_t* k)
{
    uint32_t* w = v;

	uint32_t y = w[0];
	uint32_t z = w[1];
	uint32_t sum = 0;

	int i = 0;
	while (i++ < XTROUND) {
		y += (((z << 4) ^ (z >> 5)) + z) ^ (sum + (k[sum & 3]));
		sum += XTDELTA;
		z += (((y << 4) ^ (y >> 5)) + y) ^ (sum + (k[(sum >> 11) & 3]));
	}
	w[0] = y;
	w[1] = z;
}

void XTeaDecrypt(/*uint32_t* w, */void* v, const uint32_t* k)
{
	uint32_t* w = v;

	uint32_t y = w[0];
	uint32_t z = w[1];
	uint32_t sum = XTSUM; //XTDELTA * XTROUND;

	int i = 0;
	while (i++ < XTROUND) {
		z -= (((y << 4) ^ (y >> 5)) + y) ^ (sum + (k[(sum >> 11) & 3]));
		sum -= XTDELTA;
		y -= (((z << 4) ^ (z >> 5)) + z) ^ (sum + (k[sum & 3]));
	}
	w[0] = y;
	w[1] = z;
}
