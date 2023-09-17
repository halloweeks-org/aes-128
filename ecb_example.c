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