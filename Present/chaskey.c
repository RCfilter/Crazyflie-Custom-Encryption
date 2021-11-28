/**
  Copyright © 2017 Odzhan. All Rights Reserved.

  Redistribution and use in source and binary forms, with or without
  modification, are permitted provided that the following conditions are
  met:

  1. Redistributions of source code must retain the above copyright
  notice, this list of conditions and the following disclaimer.

  2. Redistributions in binary form must reproduce the above copyright
  notice, this list of conditions and the following disclaimer in the
  documentation and/or other materials provided with the distribution.

  3. The name of the author may not be used to endorse or promote products
  derived from this software without specific prior written permission.

  THIS SOFTWARE IS PROVIDED BY AUTHORS "AS IS" AND ANY EXPRESS OR
  IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
  DISCLAIMED. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
  (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
  SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
  STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
  ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
  POSSIBILITY OF SUCH DAMAGE. */

#define R(v,n)(((v)>>(n))|((v)<<(32-(n))))
#define F(n)for(i=0;i<n;i++)
typedef unsigned int W;
typedef unsigned char B;

void chaskey_setkey(void *out, const void *in) {
    W i, *k=(W*)out;
  
    F(16) ((B*)out)[i] = ((B*)in)[i];
  
    F(2) {
      k[4] = (k[0] + k[0]) ^ (-(k[3] >> 31) & 0x87);
      k[5] = (k[1] + k[1]) | (k[0] >> 31); 
      k[6] = (k[2] + k[2]) | (k[1] >> 31); 
      k[7] = (k[3] + k[3]) | (k[2] >> 31);
      k += 4;    
    }
}

void permute(void *v) {
    W i, *x=(W*)v;
    
    F(12) {
      x[0] += x[1];
      x[1] = R(x[1],27) ^ x[0];
      x[2] += x[3];
      x[3] = R(x[3],24) ^ x[2];
      x[2] += x[1];
      x[0] = R(x[0],16) + x[3];
      x[3] = R(x[3],19) ^ x[0];
      x[1] = R(x[1],25) ^ x[2];
      x[2] = R(x[2],16);
    }
}

void chaskey_mac(void *tag, const void *data, W len, void *key) {
    B v[16], *p=(B*)data, *t=(B*)tag, *k=(B*)key;
    W i, r;
    
    // copy 128-bit master key to local memory
    F(16) v[i] = k[i];

    // absorb data
    for (;;) {
      r = (len > 16) ? 16 : len;
      
      // xor v with msg data
      F(r) v[i] ^= p[i];

      // final block?
      if (len <= 16) {
        if (len < 16) {
          // add padding bit if less than 16 bytes
          v[len] ^= 1;
        }
        // advance key
        k += (len == 16) ? 16 : 32;
        break;
      }    
      
      // encrypt data
      permute(v);
      
      // update position and length
      p += r;
      len -= r;
    }

    // encryption
    // mix key
    F(16) v[i]^=k[i];
    // encrypt
    permute(v);
    // mix key
    F(16) v[i]^=k[i];
    // return tag
    F(16) t[i]=v[i];
}
