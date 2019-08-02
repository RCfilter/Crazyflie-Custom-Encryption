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

void XTeaEncrypt(/*uint32_t* w, */void* v, const uint32_t* k);

void XTeaDecrypt(/*uint32_t* w, */void* v, const uint32_t* k);
