#include "Enclave.h"
#include "Enclave_t.h" /* print_string */
#include <stdarg.h>
#include <stdio.h> /* vsnprintf */
#include <string>

bool verbose_debug = false;

sgx_ec256_private_t p_private;
sgx_ec256_public_t p_public;
sgx_ecc_state_handle_t ecc_handle;

sgx_aes_ctr_128bit_key_t p_shared_key_128;

char *PSK_A = "I AM ALICE";
char *PSK_B = "I AM BOBOB";

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

/************************
* BEGIN [2. E_B key pair generation]
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
* END   [2. E_B key pair generation]
*************************/

/************************
* BEGIN [3. E_B compute shared secret]
*************************/
sgx_status_t computeSharedKey(sgx_ec256_public_t p_public_A)
{
  sgx_status_t status;

  sgx_ec256_dh_shared_t p_shared_key;

  status = sgx_ecc256_compute_shared_dhkey(&p_private, &p_public_A, &p_shared_key, ecc_handle);
  if (status!=SGX_SUCCESS){
    return status;
  }

  for (int i = 0; i < SGX_AESCTR_KEY_SIZE; ++i)
  {
      p_shared_key_128[i] = p_shared_key.s[i];
  }
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
  memset(p_dst, 0, BUFLEN);

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
  memset(p_dst, 0, BUFLEN);

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


sgx_status_t checkPSK(char* encrypted_PSK_A)
{
	if (verbose_debug) {printf("From Enclave: Encrypted PSK_A is %s\n", encrypted_PSK_A);}

	size_t decMessageLen = strlen(PSK_A);
	char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
  size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(PSK_A)); 

	decryptMessage(encrypted_PSK_A,encMessageLen,decMessage,decMessageLen);
	decMessage[decMessageLen] = '\0';

  int cmp = strcmp(PSK_A, decMessage);

  if (!cmp) {
    printf("From Enclave: PSK_A match!\n");
    free(decMessage);
    return SGX_SUCCESS;
  } else {
    printf("From Enclave: PSK_A doesn't match!\n");
    free(decMessage);
    return SGX_ERROR_UNEXPECTED;
  }
}

sgx_status_t getPSK()
{
	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(PSK_B)); 
	char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));

	encryptMessage(PSK_B, strlen(PSK_B), encMessage, encMessageLen);
	encMessage[encMessageLen] = '\0';
	if (verbose_debug) {printf("From Enclave: Encrypted PSK_B is %s\n", encMessage);}
  if (verbose_debug) {printf("PSK_B LEN: %d, %d\n", encMessageLen, strlen(encMessage));}

  printf("From Enclave: Encrypted PSK_B computed\n");

  ocall_send_PSK(encMessage);

  free(encMessage);

  return SGX_SUCCESS;
}


sgx_status_t solveChallenge(char* encrypted_challenge)
{
/************************
* BEGIN [6. E_B decrypts the challenge]
*************************/
	if (verbose_debug) {printf("From Enclave: Encrypted challenge is %s\n", encrypted_challenge);}

	size_t decMessageLen = 8;
	char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
  size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + 8); 

	decryptMessage(encrypted_challenge,encMessageLen,decMessage,decMessageLen);
	decMessage[decMessageLen] = '\0';
	
  if (verbose_debug) {printf("DEC LEN: %d | %d, %d\n", decMessageLen, encMessageLen, strlen(encrypted_challenge));}
  if (verbose_debug) {printf("Decrypted message: %s\n", decMessage);}

  uint32_t a1; 
  uint32_t b1; 
  memcpy((unsigned char *) &a1, &decMessage[0], 4);
  memcpy((unsigned char *) &b1, &decMessage[4], 4);

  free(decMessage);

  if (verbose_debug) {printf("From Enclave: Chose a1=%d & b1=%d for challenge\n", a1, b1);}
/************************
* END   [6. E_B decrypts the challenge]
*************************/


/************************
* BEGIN [7. E_B computes and encrypts the response]
*************************/
  unsigned int solved = a1+b1;
  if (verbose_debug) {printf("RES: %d\n", solved);}


  int bufferLen = 4;
  unsigned char* bufferToEncrypt = (unsigned char *) malloc((bufferLen+1)*sizeof(unsigned char));

  memcpy(&bufferToEncrypt[0], (unsigned char *) &solved, 4);
  bufferToEncrypt[bufferLen] = '\0';

  if (verbose_debug) {printf("Buffer: %s\n", bufferToEncrypt);}

	// The encrypted message will contain the MAC, the IV, and the encrypted message itself.
	size_t encMessageLen1 = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + bufferLen); 
	char *encMessage = (char *) malloc((encMessageLen1+1)*sizeof(char));

	encryptMessage((char*)bufferToEncrypt, bufferLen, encMessage, encMessageLen1);
	encMessage[encMessageLen1] = '\0';
  if (verbose_debug) {printf("ENC LEN: %d, %d\n", encMessageLen1, strlen(encMessage));}

	if (verbose_debug) {printf("Encrypted message: %s\n", encMessage);}


  printf("From Enclave: Encrypted challenge response computed\n");

  ocall_send_challenge_response(encMessage);

  free(bufferToEncrypt);
  free(encMessage);


/************************
* END   [7. E_B computes and encrypts the response]
*************************/

  return SGX_SUCCESS;
}