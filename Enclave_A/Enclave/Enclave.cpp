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

// sgx_status_t getPSK()
// {
//   sgx_status_t status;

//   memset(iv, 0, 16); // Based on https://moodle-app2.let.ethz.ch/mod/forum/discuss.php?d=93167
  
//   uint8_t PSK_cipher[64];
//   memset(PSK_cipher, 0, 64);

//   status = sgx_aes_ctr_encrypt((const sgx_aes_ctr_128bit_key_t*)&p_shared_key_128, (const uint8_t*)PSK, (const uint32_t)strlen((char*)PSK), (uint8_t*)iv, (const uint32_t)1, (uint8_t*)PSK_cipher);

//   printf("PLAINT: %s \n", (char *)PSK);
//   printf("CIPHER: %s \n", (char *)PSK_cipher);

//   uint8_t result[64];
//   memset(result, 0, 64);

//   status = sgx_aes_ctr_decrypt((const sgx_aes_ctr_128bit_key_t*)&p_shared_key_128, (const uint8_t*)PSK_cipher, (const uint32_t)strlen((char*)PSK_cipher), (uint8_t*)iv, (const uint32_t)1, (uint8_t*)result);
//   printf("RESULT: %s \n", (char *)result);

//   return status;
// }

// sgx_status_t getPSK()
// {
//   sgx_status_t status;

//   uint8_t iv1[16];
//   memset(iv1, 0, 16); 

//   uint8_t* original = (uint8_t*) "I AM ALICE";
//   printf("LEN KEY: %d\n", strlen((char *)&p_shared_key_128));

//   uint8_t cipher[64];
//   memset(cipher, 0, 64);

//   uint8_t plaintext[64];
//   memset(plaintext, 0, 64);

//   printf("KEY: %s\n", (char*)&p_shared_key_128);
//   printf("IV: %s\n", (char*)iv1);

//   status = sgx_aes_ctr_encrypt(&p_shared_key_128, (const uint8_t*) original, strlen((char *)original), iv1, 128, cipher);
//   printf("IV: %s\n", iv1);
//   printf("LEN ORIG: %d\n", strlen((char *)original));
//   if (status!=SGX_SUCCESS){
//     printf("ERR encrypt\n");
//   }

//   status = sgx_aes_ctr_decrypt(&p_shared_key_128, (const uint8_t*) cipher, strlen((char *)cipher), iv1, 128, plaintext);
//   printf("IV: %s\n", iv1);
//   printf("LEN CIPHER: %d\n", strlen((char *)cipher));
//   if (status!=SGX_SUCCESS){
//     printf("ERR decrypt\n");
//   }

//   printf("original: %s\ncipher: %s\ndecrypted: %s\n", (char *)original, (char *)cipher, (char *)plaintext);

//   return status;
// }


sgx_status_t getPSK()
{
  sgx_status_t status;

  uint8_t cipher[256];
  memset(cipher, 0, 256);

  uint8_t p_ctr[16] = { 4, 3, 2, 1, 0 };
	uint32_t ctr_inc_bits = 32;
	uint32_t src_len = 256;
	uint8_t p_src[src_len] = { 65, 66, 67, 68 };
	uint32_t dst_len = 256;

	sgx_aes_ctr_128bit_key_t p_key[16] = { 0, 7, 7, 8, 3, 1, 4, 4, 9, 8, 0, 0, 0, 0, 0 };

	sgx_aes_ctr_encrypt((const sgx_aes_ctr_128bit_key_t*) p_key,
			(const uint8_t*) p_src, src_len, p_ctr, ctr_inc_bits, cipher);


	uint8_t d_data[dst_len];
  memset(cipher, 0, dst_len);

	sgx_aes_ctr_decrypt((const sgx_aes_gcm_128bit_key_t*) p_key, cipher, dst_len,
			p_ctr, ctr_inc_bits, d_data);

  printf("original: %s\ncipher: %s\ndecrypted: %s\n", (char *)p_src, (char *)cipher, (char *)d_data);

  return status;
}