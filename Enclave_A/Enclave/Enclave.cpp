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

uint32_t a; 
uint32_t b; 

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
* END [2. E_A key pair generation]
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

  printf("From Enclave: Shared Key computed\n");

  return status;
}
/************************
* END [3. E_B compute shared secret]
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


sgx_status_t getPSK()
{

	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(PSK_A)); 
	char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));

	encryptMessage(PSK_A, strlen(PSK_A), encMessage, encMessageLen);
	encMessage[encMessageLen] = '\0';
  if (verbose_debug) {printf("PSK_A LEN: %d, %d\n", encMessageLen, strlen(encMessage));}

	if (verbose_debug) {printf("From Enclave: Encrypted PSK_A is %s\n", encMessage);}

  printf("From Enclave: Encrypted PSK_A computed\n");

  ocall_send_PSK(encMessage);

  free(encMessage);

  return SGX_SUCCESS;
}

sgx_status_t checkPSK(char* encrypted_PSK_B)
{
  if (verbose_debug) {printf("From Enclave: Encrypted PSK_B is %s\n", encrypted_PSK_B);}

	size_t decMessageLen = strlen(PSK_B);
	char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
  size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + strlen(PSK_B)); 

	decryptMessage(encrypted_PSK_B,encMessageLen,decMessage,decMessageLen);
	decMessage[decMessageLen] = '\0';

  int cmp = strcmp(PSK_B, decMessage);

  if (!cmp) {
    printf("From Enclave: PSK_B match!\n");
    free(decMessage);
    return SGX_SUCCESS;
  } else {
    printf("From Enclave: PSK_B doesn't match!\n");
    free(decMessage);
    return SGX_ERROR_UNEXPECTED;
  }
}



/************************
* BEGIN [4. E_A generates and encrypts the challenge]
*************************/
sgx_status_t getChallenge()
{
  sgx_status_t status;

  //based on https://community.intel.com/t5/Intel-Software-Guard-Extensions/Using-random-library-within-enclave/td-p/1074122
  status = sgx_read_rand((unsigned char *) &a, 4);
  if (status!=SGX_SUCCESS){
    return status;
  }
  status = sgx_read_rand((unsigned char *) &b, 4);
  if (status!=SGX_SUCCESS){
    return status;
  }

  if (verbose_debug) {printf("From Enclave: Chose a=%d & b=%d for challenge\n", a, b);}

  int bufferLen = 2*4;
  unsigned char* bufferToEncrypt = (unsigned char *) malloc((bufferLen+1)*sizeof(unsigned char));

  memcpy(&bufferToEncrypt[0], (unsigned char *) &a, 4);
  memcpy(&bufferToEncrypt[4], (unsigned char *) &b, 4);
  bufferToEncrypt[bufferLen] = '\0';

  if (verbose_debug) {printf("Buffer: %s\n", bufferToEncrypt);}



	// The encrypted message will contain the MAC, the IV, and the encrypted message itself.
	size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + bufferLen); 
	char *encMessage = (char *) malloc((encMessageLen+1)*sizeof(char));

	encryptMessage((char*)bufferToEncrypt, bufferLen, encMessage, encMessageLen);
	encMessage[encMessageLen] = '\0';
  if (verbose_debug) {printf("ENC LEN: %d | %d, %d\n", strlen((char*)bufferToEncrypt), encMessageLen, strlen(encMessage));}

	if (verbose_debug) {printf("Encrypted message: %s\n", encMessage);}


  printf("From Enclave: Encrypted challenge computed\n");

  ocall_send_challenge(encMessage);

  free(bufferToEncrypt);
  free(encMessage);

  return status;
}
/************************
* END [4. E_A generates and encrypts the challenge]
*************************/


/************************
* BEGIN [5. E_A decrypts and verifies the challenge]
*************************/
sgx_status_t checkChallengeResponse(char* encrypted_challenge_response)
{
	if (verbose_debug) {printf("From Enclave: Encrypted challenge response is %s\n", encrypted_challenge_response);}

	size_t decMessageLen = 4;
	char *decMessage = (char *) malloc((decMessageLen+1)*sizeof(char));
  size_t encMessageLen = (SGX_AESGCM_MAC_SIZE + SGX_AESGCM_IV_SIZE + 4); 

	decryptMessage(encrypted_challenge_response,encMessageLen,decMessage,decMessageLen);
	decMessage[decMessageLen] = '\0';
	
  if (verbose_debug) {printf("Decrypted message: %s\n", decMessage);}

  unsigned int solved_A = a+b;
  if (verbose_debug) {printf("RES: %d\n", solved_A);}

  unsigned int solved_B; 
  memcpy((unsigned int *) &solved_B, &decMessage[0], 4);

  free(decMessage);

  int cmp = (solved_A == solved_B);
  printf("From Enclave: Challenge result computed\n");
  ocall_send_result(cmp);

  if (cmp) {
    if (verbose_debug) {printf("From Enclave: Result match! (%d)\n", solved_B);}
  } else {
    if (verbose_debug) {printf("From Enclave: Result doesn't match! (%d != %d)\n", solved_B, solved_A);}
  }

  return SGX_SUCCESS;
}
/************************
* END [5. E_A decrypts and verifies the challenge]
*************************/