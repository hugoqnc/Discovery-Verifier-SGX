#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string>

int enclave_secret = 1337;
sgx_ec256_private_t p_private;
sgx_ec256_public_t p_public;
sgx_ecc_state_handle_t ecc_handle;

sgx_aes_ctr_128bit_key_t p_shared_key_128;
uint8_t iv[16];

//uint8_t PSK[11] = "I AM ALICE";
uint8_t* PSK = (uint8_t*) "I AM ALICE";

int printf(const char* fmt, ...)
{
    char buf[BUFSIZ] = { '\0' };
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, BUFSIZ, fmt, ap);
    va_end(ap);
    ocall_print_string(buf);
    return (int)strnlen(buf, BUFSIZ - 1) + 1;
}

sgx_status_t printSecret()
{
  char buf[BUFSIZ] = {"From Enclave: Hello from the enclave.\n"};
  ocall_print_string(buf);
  printf("From Enclave: Another way to print from the Enclave. My secret is %u.\n", enclave_secret);
  return SGX_SUCCESS;
}

/************************
* BEGIN [2. E_A key pair generation]
*************************/
sgx_status_t generateKeyPair()
{
  sgx_status_t status;

  status = sgx_ecc256_open_context(&ecc_handle);
  if (status!=SGX_SUCCESS){
    return status;
  }

  status = sgx_ecc256_create_key_pair(&p_private, &p_public, ecc_handle);

  printf("From Enclave: Key generated\n");

  ocall_send_public_key(p_public);

  return status;
}
/************************
* END   [2. E_A key pair generation]
*************************/

/************************
* BEGIN [3. E_B compute shared secret]
*************************/
sgx_status_t computeSharedKey(sgx_ec256_public_t p_public_B)
{
  sgx_status_t status;

  sgx_ec256_dh_shared_t p_shared_key;

  status = sgx_ecc256_compute_shared_dhkey(&p_private, &p_public_B, &p_shared_key, ecc_handle);
  if (status!=SGX_SUCCESS){
    return status;
  }

  for (int i = 0; i < SGX_AESCTR_KEY_SIZE; ++i)
  {
      p_shared_key_128[i] = p_shared_key.s[i];
  }
  
  
  // printf("KEY A: %s | %s\n",p_public.gx,p_public.gy);
  // printf("KEY B: %s | %s\n",p_public_B.gx,p_public_B.gy);
  // printf("S. DH: %s \n", p_shared_key_128);

  printf("From Enclave: Shared Key computed\n");

  
  return status;
}
/************************
* END   [3. E_B compute shared secret]
*************************/

// The following functions encryptMessage and decryptMessage are based on https://github.com/rodolfoams/sgx-aes-gcm
// It is probably too much compared to simply using "sgx_aes_ctr_encrypt" and "sgx_aes_ctr_decrypt",
// however I wasn't able to make the decrypted text match the original text with these functions despite having
// spent an enormous amount of time on it. 

#define BUFLEN 2048

void decryptMessage(char *encMessageIn, size_t len, char *decMessageOut, size_t lenOut)
{
	uint8_t *encMessage = (uint8_t *) encMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	sgx_rijndael128GCM_decrypt(
		&p_shared_key_128,
		encMessage + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		lenOut,
		p_dst,
		encMessage + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) encMessage);
	memcpy(decMessageOut, p_dst, lenOut);
}

void encryptMessage(char *decMessageIn, size_t len, char *encMessageOut, size_t lenOut)
{
	uint8_t *origMessage = (uint8_t *) decMessageIn;
	uint8_t p_dst[BUFLEN] = {0};

	// Generate the IV (nonce)
	sgx_read_rand(p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE);

	sgx_rijndael128GCM_encrypt(
		&p_shared_key_128,
		origMessage, len, 
		p_dst + SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE,
		p_dst + SGX_AESGCM_MAC_SIZE, SGX_AESGCM_IV_SIZE,
		NULL, 0,
		(sgx_aes_gcm_128bit_tag_t *) (p_dst));	
	memcpy(encMessageOut,p_dst,lenOut);
}

// sgx_status_t testEncryption()
// {
//   char *message = "Hello, crypto enclave!";
// 	printf("Original message: %s\n", message);

// 	// The encrypted message will contain the MAC, the IV, and the encrypted message itself.
// 	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(message)); 
// 	char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));

// 	encryptMessage(message, strlen(message), encMessage, encMessageLen);
// 	encMessage[encMessageLen] = '\0';
// 	printf("Encrypted message: %s\n", encMessage);

//   // The decrypted message will contain the same message as the original one.
// 	size_t decMessageLen = strlen(message);
// 	char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));

// 	decryptMessage(encMessage,encMessageLen,decMessage,decMessageLen);
// 	decMessage[decMessageLen] = '\0';
// 	printf("Decrypted message: %s\n", decMessage);

//   return SGX_SUCCESS;
// }

sgx_status_t getPSK()
{
  char *message = "I AM ALICE";
	//printf("Original message: %s\n", message);

	// The encrypted message will contain the MAC, the IV, and the encrypted message itself.
	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(message)); 
	char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));

	encryptMessage(message, strlen(message), encMessage, encMessageLen);
	encMessage[encMessageLen] = '\0';
	//printf("Encrypted message: %s\n", encMessage);

  //printf("From Enclave: Encrypted PSK computed\n");

  ocall_send_PSK(encMessage);

  return SGX_SUCCESS;
}


