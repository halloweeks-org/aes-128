# AES-128 ECB AND CBC

## AES-128 ECB Encrypt Decrypt Example

There is no padding supported, block size required 16 bytes

```
#include <stdio.h>
#include "aes_128.h"

int main() {
  // example key
  uint8_t key[16] = {
    0xB2, 0x4F, 0x9A, 0x66, 0xF6, 0x43, 0xC8, 0xBF,
    0xB7, 0x1F, 0x62, 0xDC, 0x18, 0x91, 0x3C, 0xE5
  };
	
  // stored rounds keys 
  uint32_t rk[44];

  uint8_t data[AES_BLOCK_SIZE] = "This is test ecb";
  uint8_t ciphertext[AES_BLOCK_SIZE];
  uint8_t plaintext[AES_BLOCK_SIZE];
  
  printf("Original data: ");
  for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
  	printf("0x%02X, ", data[i]);
  }
  printf("\n\n");
  
  // AES-128 Key Expansion for encryption
  AES_encrypt_init(key, rk);
  
  // AES-128 Encrypt data ecb
  AES_encrypt(data, ciphertext, rk);
  
  printf("Encrypted data: ");
  for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
  	printf("0x%02X, ", ciphertext[i]);
  }
  printf("\n\n");
  
  // AES-128 Key Expansion decryption
  AES_decrypt_init(key, rk);
  
  // AES-128 Encrypt data ecb
  AES_decrypt(ciphertext, plaintext, rk);
  
  printf("Decrypted data: ");
  for (uint8_t i = 0; i < AES_BLOCK_SIZE; i++) {
  	printf("0x%02X, ", plaintext[i]);
  }
  printf("\n\n");
  
  return 0;
}
```

## AES-128 CBC Encrypt Decrypt
There is no padding supported, cbc mode support multiple blocks 

```
#include <stdio.h>
#include "aes_128.h"

int main() {
  uint8_t key[16] = {
    0xB2, 0x4F, 0x9A, 0x66, 0xF6, 0x43, 0xC8, 0xBF,
	0xB7, 0x1F, 0x62, 0xDC, 0x18, 0x91, 0x3C, 0xE5
  };
  
  
	
	uint8_t iv[16] = {
		0x32, 0x3A, 0xAC, 0xCA, 0x21, 0x48, 0xC9, 0x58,
		0x78, 0x0A, 0xD9, 0x66, 0x64, 0xBA, 0x1E, 0x38
	};
	
	uint32_t rk[44];
	
	// 2 blocks data is same "This is test cbc" in hexdecimal
	uint8_t data[32] = {
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x62, 0x63,
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20,
		0x74, 0x65, 0x73, 0x74, 0x20, 0x63, 0x62, 0x63,
	};
	
  uint8_t ciphertext[32];
  uint8_t plaintext[32];
  
  printf("Original data: ");
  
  for (uint8_t i = 0; i < AES_BLOCK_SIZE * 2; i++) {
  	printf("0x%02X, ", data[i]);
  }
  
  printf("\n\n");
  
  // AES-128 Key Expansion for encryption
  AES_encrypt_init(key, rk);
  
  // encrypt 32 byte data in cbc mode
  AES_cbc_encrypt(data, 32, ciphertext, rk, iv);
  
  printf("Encrypted data: ");
  for (uint8_t i = 0; i < AES_BLOCK_SIZE * 2; i++) {
  	printf("0x%02X, ", ciphertext[i]);
  }
  printf("\n\n");
  
  // AES-128 Key Expansion for decryption
  AES_decrypt_init(key, rk);
  
  // decrypt 32 byte data in cbc mode
  AES_cbc_decrypt(ciphertext, 32, plaintext, rk, iv);
  
  printf("Decrypted data: ");
  for (uint8_t i = 0; i < AES_BLOCK_SIZE * 2; i++) {
  	printf("0x%02X, ", plaintext[i]);
  }
  printf("\n\n");
  
  return 0;
}
```
