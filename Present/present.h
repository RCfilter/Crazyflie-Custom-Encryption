#include <stdint.h>
#include <stdio.h>
#include <string.h>

typedef uint16_t u16;
typedef int16_t s16;

void Encrypt(void *state, const u16 *aKey);

void Decrypt(void *state, const u16 *aKey);
