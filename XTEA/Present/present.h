#include <stdint.h>
#include <stdio.h>
#include <string.h>

/*
 * This file has been modified by the Wireless Innovation and Cybersecurity Lab of George Mason University
 * This project was overseen by Dr. Kai Zeng from the Department of Electrical and Computer Engineering
 * Contributing Members: David Rudo, Brandon Fogg, Thomas Lu, Matthew Chang, Yaqi He, Shrinath Iyer
 */

typedef uint16_t u16;
typedef int16_t s16;

void Encrypt(uint8_t *state, const u16 *aKey);

void Decrypt(uint8_t *state, const u16 *aKey);

void EncryptHelper(u16 *state, const u16 *aKey);

void DecryptHelper(u16 *state, const u16 *aKey);
