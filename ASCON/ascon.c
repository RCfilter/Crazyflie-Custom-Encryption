/* 
 * ASCON implementors: Christoph Dobraunig, Martin Schläffer
 * 
 * Fall 2021
 * ECE493 Secure Swarm ASCON wrapper
 * 
 * The purpose of this file is to contain ASCON functions 
 * in a single source code file and to test with 31/32-byte 
 * messages(main.c) for encrypted Crazyflie communications
 * 
 * A: Roen R, Chris N, Alcides R
 */

#include "api.h"
#include "ascon.h"
#include "crypto_aead.h"
#include "permutations.h"
#include "printstate.h"
#include "word.h"

#include <inttypes.h>
#include <stdio.h>
#include <string.h>


/*
 * print utility
 */
void printword(const char* text, const word_t x) {
  printf("%s=%016" PRIx64 "\n", text, WORDTOU64(x));
}

void printstate(const char* text, const state_t* s) {
  printf("%s:\n", text);
  printword("  x0", s->x0);
  printword("  x1", s->x1);
  printword("  x2", s->x2);
  printword("  x3", s->x3);
  printword("  x4", s->x4);
}

void disp(const unsigned char* k, const unsigned char* npub, 
          const unsigned char* m, unsigned long long mlen,
          const unsigned char* ad, unsigned long long adlen,
          const unsigned char* c, unsigned long long clen); 

/*
 * Encrypt
 */
int crypto_aead_encrypt(unsigned char* c, unsigned long long* clen,
                        const unsigned char* m, unsigned long long mlen,
                        const unsigned char* ad, unsigned long long adlen,
                        const unsigned char* nsec, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  /* set ciphertext size */
  *clen = mlen + CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  state_t s;
  s.x0 = ASCON_128_IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  //printstate("initialization", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
      s.x0 ^= LOADBYTES(ad, 8);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x0 ^= LOADBYTES(ad, adlen);
    s.x0 ^= PAD(adlen);
    P6(&s);
  }
  /* domain separation */
  s.x4 ^= 1;
  //printstate("process associated data", &s);

  /* full plaintext blocks */
  while (mlen >= ASCON_128_RATE) {
    s.x0 ^= LOADBYTES(m, 8);
    STOREBYTES(c, s.x0, 8);
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    mlen -= ASCON_128_RATE;
  }
  /* final plaintext block */
  s.x0 ^= LOADBYTES(m, mlen);
  STOREBYTES(c, s.x0, mlen);
  s.x0 ^= PAD(mlen);
  c += mlen;
  //printstate("process plaintext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  //printstate("finalization", &s);

  /* set tag */
  STOREBYTES(c, s.x3, 8);
  STOREBYTES(c + 8, s.x4, 8);
  return 0;
}

/*
 * Decrypt
 */
int crypto_aead_decrypt(unsigned char* m, unsigned long long* mlen,
                        unsigned char* nsec, const unsigned char* c,
                        unsigned long long clen, const unsigned char* ad,
                        unsigned long long adlen, const unsigned char* npub,
                        const unsigned char* k) {
  (void)nsec;

  if (clen < CRYPTO_ABYTES) return -1;

  /* set plaintext size */
  *mlen = clen - CRYPTO_ABYTES;

  /* load key and nonce */
  const uint64_t K0 = LOADBYTES(k, 8);
  const uint64_t K1 = LOADBYTES(k + 8, 8);
  const uint64_t N0 = LOADBYTES(npub, 8);
  const uint64_t N1 = LOADBYTES(npub + 8, 8);

  /* initialize */
  state_t s;
  s.x0 = ASCON_128_IV;
  s.x1 = K0;
  s.x2 = K1;
  s.x3 = N0;
  s.x4 = N1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  //printstate("initialization", &s);

  if (adlen) {
    /* full associated data blocks */
    while (adlen >= ASCON_128_RATE) {
      s.x0 ^= LOADBYTES(ad, 8);
      P6(&s);
      ad += ASCON_128_RATE;
      adlen -= ASCON_128_RATE;
    }
    /* final associated data block */
    s.x0 ^= LOADBYTES(ad, adlen);
    s.x0 ^= PAD(adlen);
    P6(&s);
  }
  /* domain separation */
  s.x4 ^= 1;
  //printstate("process associated data", &s);

  /* full ciphertext blocks */
  clen -= CRYPTO_ABYTES;
  while (clen >= ASCON_128_RATE) {
    uint64_t c0 = LOADBYTES(c, 8);
    STOREBYTES(m, s.x0 ^ c0, 8);
    s.x0 = c0;
    P6(&s);
    m += ASCON_128_RATE;
    c += ASCON_128_RATE;
    clen -= ASCON_128_RATE;
  }
  /* final ciphertext block */
  uint64_t c0 = LOADBYTES(c, clen);
  STOREBYTES(m, s.x0 ^ c0, clen);
  s.x0 = CLEARBYTES(s.x0, clen);
  s.x0 |= c0;
  s.x0 ^= PAD(clen);
  c += clen;
  //printstate("process ciphertext", &s);

  /* finalize */
  s.x1 ^= K0;
  s.x2 ^= K1;
  P12(&s);
  s.x3 ^= K0;
  s.x4 ^= K1;
  //printstate("finalization", &s);

  /* set tag */
  uint8_t t[16];
  STOREBYTES(t, s.x3, 8);
  STOREBYTES(t + 8, s.x4, 8);

  /* verify tag (should be constant time, check compiler output) */
  int result = 0;
  for (int i = 0; i < CRYPTO_ABYTES; ++i) result |= c[i] ^ t[i];
  result = (((result - 1) >> 8) & 1) - 1;

  return result;
}

/*
 * main
 */
int error = 0;

int main(void) {

	static unsigned char k[16];       // Key (128-bit)
	static unsigned char c[31+32];   // Cipher text, tag appended
	static unsigned char ad[1];      // Associated data
	static unsigned char m[31];      // Plain text
	static unsigned char nsec[16];   // Nonce (secret) (void)
	static unsigned char npub[16];   // Nonce (public message number)
    unsigned long long adlen;      // max 1 byte (pk Header)
    unsigned long long mlen;       // max 31 byte (pk Data)
    unsigned long long clen;       // exactly the same length as PT
    unsigned long long tlen;       // void, Tag is appended to CT
    unsigned int i;    


    /* Assign values of test vector*/
    mlen=24;       // How will radiolink.c know the mlen? strlen
    clen=mlen+16;  // What does clen depends on? mlen + 128 bit tag
    adlen=0;       // using assocated data? 0x00 or void
    tlen=0;       // void

    /* AEAD is tested extensively, known valued test vectors 
    * serve us to explore this algorithm before use in our 
    * particular use-case test vectors are: Count = 793, 794 from
    * LWC_AEAD_KAT_128_128.txt accompanies ASCON implementaion
    * AD =   , CT = BC820DBDF7A4631C01A8807A44254B42AC6BB490DA1E000A
    * AD = 00, CT = BD4640C4DA2FFA565004C927913485A90B18BE0F3741A393
    */
  
    /* Initialize */
    for (i=0; i<24; i++) m[i]=i;    // PT = 000102030405060708090A0B0C0D0E0F1011121314151617
    for (i=0; i<1; i++) ad[i]=0;    // AD = 00 
    for (i=0; i<16; i++) k[i]=i;    // Key = 000102030405060708090A0B0C0D0E0F
    for (i=0; i<16; i++) nsec[i]=i;  // (void) 000102030405060708090A0B0C0D0E0F 
    for (i=0; i<16; i++) npub[i]=i;  // Nonce = 000102030405060708090A0B0C0D0E0F
    
    disp(k,npub,m,mlen,ad,adlen,c,clen);
    printf("Plain text length: %lld \n", mlen);
    printf("Cipher text length: %lld \n\n", clen);

    printf(" --- Encrypt ---\n");
    crypto_aead_encrypt(c,&clen,m,mlen,ad,adlen,nsec,npub,k);
    disp(k,npub,m,mlen,ad,adlen,c,clen);

    printf("\n -- Reinitialize --\n"); 
    for (i=0; i<31; i++) m[i]=0;    // reinitialize 'm' before decrypt!
    printf("Plain text (m):  ");
    for (i=0; i<mlen; i++) {
      printf("%02X", m[i]);
    }
    printf("\n\n");

    printf(" -- Truncate the MAC (Warning!)--\n");
    for (i=clen; i>31; i--) {
      c[i] = 0;
    }
    printf("\nCipher text (c):  ");
    for (i=0; i<clen; i++) {
      printf("%02X", c[i]);
    }
    printf("\n\n");
  
    printf(" --- Decrypt ---\n"); //check for error for decrypt
    error = crypto_aead_decrypt(m,&mlen,nsec,c,clen,ad,adlen,npub,k);
    disp(k,npub,m,mlen,ad,adlen,c,clen);
    
    printf("\nVerification of the tag\nError=%d\n", error);

	return 0;
}

/*
 * too many print statements
 */ 
void disp(const unsigned char* k, const unsigned char* npub, 
          const unsigned char* m, unsigned long long mlen,
          const unsigned char* ad, unsigned long long adlen,
          const unsigned char* c, unsigned long long clen) {
    unsigned int i;
    printf("Key (k):  ");
    for (i=0; i<16; i++) {
      printf("%02X", k[i]);
    }
    printf("\n");

    printf("Nonce (n):  ");
    for (i=0; i<16; i++) {
      printf("%02X", npub[i]);
    }
    printf("\n");

    printf("Plain text (m):  ");
    for (i=0; i<mlen; i++) {
      printf("%02X", m[i]);
    }
    printf("\n");

    printf("Cipher text (c): ");
    for (i=0; i<clen; i++) {
      printf("%02X", c[i]);
    }
    printf("\n");

    printf("Associated data (ad): ");
    for (i=0; i<adlen; i++) {
      printf("%02X", ad[i]);
    }
    printf("\n");
}