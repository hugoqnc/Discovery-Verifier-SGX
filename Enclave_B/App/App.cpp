#include <stdio.h>
#include <string>
#include <assert.h>

#include <iostream>
#include <fstream>

#include <unistd.h>
#include <pwd.h>

#include "sgx_urts.h"
#include "App.h"
#include "Enclave_u.h"

/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;

typedef struct _sgx_errlist_t {
    sgx_status_t err;
    const char *msg;
    const char *sug; /* Suggestion */
} sgx_errlist_t;

sgx_ec256_public_t p_public_A;
sgx_ec256_public_t p_public_B;

char* encrypted_PSK_A;
char* encrypted_PSK_B;

char* encrypted_challenge;

/* Error code returned by sgx_create_enclave */
static sgx_errlist_t sgx_errlist[] = {
    {
        SGX_ERROR_UNEXPECTED,
        "Unexpected error occurred.",
        NULL
    },
    {
        SGX_ERROR_INVALID_PARAMETER,
        "Invalid parameter.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_MEMORY,
        "Out of memory.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_LOST,
        "Power transition occurred.",
        "Please refer to the sample \"PowerTransition\" for details."
    },
    {
        SGX_ERROR_INVALID_ENCLAVE,
        "Invalid enclave image.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ENCLAVE_ID,
        "Invalid enclave identification.",
        NULL
    },
    {
        SGX_ERROR_INVALID_SIGNATURE,
        "Invalid enclave signature.",
        NULL
    },
    {
        SGX_ERROR_OUT_OF_EPC,
        "Out of EPC memory.",
        NULL
    },
    {
        SGX_ERROR_NO_DEVICE,
        "Invalid SGX device.",
        "Please make sure SGX module is enabled in the BIOS, and install SGX driver afterwards."
    },
    {
        SGX_ERROR_MEMORY_MAP_CONFLICT,
        "Memory map conflicted.",
        NULL
    },
    {
        SGX_ERROR_INVALID_METADATA,
        "Invalid enclave metadata.",
        NULL
    },
    {
        SGX_ERROR_DEVICE_BUSY,
        "SGX device was busy.",
        NULL
    },
    {
        SGX_ERROR_INVALID_VERSION,
        "Enclave version was invalid.",
        NULL
    },
    {
        SGX_ERROR_INVALID_ATTRIBUTE,
        "Enclave was not authorized.",
        NULL
    },
    {
        SGX_ERROR_ENCLAVE_FILE_ACCESS,
        "Can't open enclave file.",
        NULL
    },
};

/* Check error conditions for loading enclave */
void print_error_message(sgx_status_t ret)
{
    size_t idx = 0;
    size_t ttl = sizeof sgx_errlist/sizeof sgx_errlist[0];

    for (idx = 0; idx < ttl; idx++) {
        if(ret == sgx_errlist[idx].err) {
            if(NULL != sgx_errlist[idx].sug)
                printf("Info: %s\n", sgx_errlist[idx].sug);
            printf("Error: %s\n", sgx_errlist[idx].msg);
            break;
        }
    }

    if (idx == ttl)
    	printf("Error code is 0x%X. Please refer to the \"Intel SGX SDK Developer Reference\" for more details.\n", ret);
}

/* Initialize the enclave:
 *   Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS) {
        print_error_message(ret);
        return -1;
    }
    return 0;
}

/* OCall functions */
void ocall_print_string(const char *str)
{
    /* Proxy/Bridge will check the length and null-terminate
     * the input string to prevent buffer overflow.
     */
    printf("%s", str);
}


void ocall_send_public_key(sgx_ec256_public_t p_public){
    p_public_B = p_public;
    printf("From App: Received p_public_B\n");
}

void ocall_send_PSK(char *encMessage){
    size_t encMessageLen = strlen(encMessage); 
	encrypted_PSK_B = (char *) malloc((encMessageLen+1)*sizeof(char));
    strcpy(encrypted_PSK_B, encMessage);
    //printf("APP Encrypted mes: %s\n", encMessage);
    //printf("APP Encrypted mes: %s\n", encrypted_PSK_B);
    printf("From App: Received encrypted_PSK_B\n");
}


void wait_for_file(std::string filePath){
    std::cout << "From App: Waiting for '" << filePath << "'\n";

    // Based on https://stackoverflow.com/questions/18100391/check-if-a-file-exists-without-opening-it
    bool exists = false;
    while(!exists){
        int res = access(filePath.c_str(), R_OK);
        if (res<0) {            
            sleep(1);
        } else {
            exists = true;
            sleep(4); // give the time to the file to be written
        }
    }
    std::cout << "From App: Received file '" << filePath << "'\n";
}

void parse_public_key(){
    //Based on https://stackoverflow.com/questions/3811328/try-to-write-char-to-a-text-file/3811367

    std::ifstream in("../p_public_A.txt");
    in.read((char*)::p_public_A.gx, SGX_ECP256_KEY_SIZE);
    in.read((char*)::p_public_A.gy, SGX_ECP256_KEY_SIZE);
    in.close();

    // printf("KEY: %s | %s\n", p_public_A.gx, p_public_A.gy);
    printf("From App: Received p_public_A\n");
}

void export_public_key(){
    //printf("KEY: %s | %s\n",p_public_A.gx,p_public_A.gy);
    
    // Based on https://stackoverflow.com/questions/3811328/try-to-write-char-to-a-text-file/3811367

    remove("../p_public_B.txt");

    // Create and open a text file
    std::ofstream newFile("../p_public_B.txt");

    // Write to the file
    newFile.write((char*)::p_public_B.gx, SGX_ECP256_KEY_SIZE);
    newFile.write((char*)::p_public_B.gy, SGX_ECP256_KEY_SIZE);

    // Close the file
    newFile.close();

    printf("From App: Exported p_public_B to filesystem\n");
}

void parse_PSK(){
    //Based on https://stackoverflow.com/questions/3811328/try-to-write-char-to-a-text-file/3811367

    std::ifstream in("../encrypted_PSK_A.txt");
    
    //Get file length
    // Based on https://stackoverflow.com/questions/2602013/read-whole-ascii-file-into-c-stdstring
    in.seekg(0, std::ios::end); 
    int length = in.tellg();
    in.seekg(0, std::ios::beg);
    encrypted_PSK_A = new char[length]; 

    in.read((char*)::encrypted_PSK_A, length);
    in.close();

    //printf("APP Encrypted mes: %s\n", encrypted_PSK_A);
    printf("From App: Received encrypted_PSK_A\n");
}

void export_PSK(){    
    // Based on https://stackoverflow.com/questions/3811328/try-to-write-char-to-a-text-file/3811367

    remove("../encrypted_PSK_B.txt");

    // Create and open a text file
    std::ofstream newFile("../encrypted_PSK_B.txt");

    // Write to the file
    size_t encMessageLen = strlen(encrypted_PSK_B); 
    newFile.write((char*)::encrypted_PSK_B, encMessageLen);

    // Close the file
    newFile.close();

    printf("From App: Exported encrypted_PSK_B to filesystem\n");
}

void parse_challenge(){
    //Based on https://stackoverflow.com/questions/3811328/try-to-write-char-to-a-text-file/3811367

    std::ifstream in("../encrypted_challenge.txt");
    
    //Get file length
    // Based on https://stackoverflow.com/questions/2602013/read-whole-ascii-file-into-c-stdstring
    in.seekg(0, std::ios::end); 
    int length = in.tellg();
    in.seekg(0, std::ios::beg);
    encrypted_challenge = new char[length]; 

    in.read((char*)::encrypted_challenge, length);
    in.close();

    //printf("APP Encrypted mes: %s\n", encrypted_challenge);
    printf("From App: Received encrypted_challenge\n");
}



/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    (void)(argc);
    (void)(argv);
    /* Initialize the enclave */
    if(initialize_enclave() < 0){
        printf("Enclave initialization failed.\n");
        return -1;
    }
    printf("From App: Enclave creation success. \n");
    
    //printf("From App: Write your protocol here ... \n");


    sgx_status_t sgx_status;

    printSecret(global_eid, &sgx_status);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /************************
    * BEGIN [2. E_B key pair generation]
    *************************/
    generateKeyPair(global_eid, &sgx_status);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }
    /************************
    * END   [2. E_B key pair generation]
    *************************/


    /************************
    * BEGIN [1. Communication between A_A & A_B]
    *************************/
    wait_for_file("../p_public_A.txt");
    parse_public_key();
    /************************
    * END   [1. Communication between A_A & A_B]
    *************************/


    /************************
    * BEGIN [3. E_B compute shared secret]
    *************************/
    computeSharedKey(global_eid, &sgx_status, p_public_A);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }
    /************************
    * END   [3. E_B compute shared secret]
    *************************/


    /************************
    * BEGIN [1. Communication between A_A & A_B]
    *************************/
    export_public_key();
    /************************
    * END   [1. Communication between A_A & A_B]
    *************************/


    /************************
    * BEGIN [1. Communication between A_A & A_B]
    *************************/
    wait_for_file("../encrypted_PSK_A.txt");
    parse_PSK();
    /************************
    * END   [1. Communication between A_A & A_B]
    *************************/

    checkPSK(global_eid, &sgx_status, encrypted_PSK_A);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    getPSK(global_eid, &sgx_status);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /************************
    * BEGIN [1. Communication between A_A & A_B]
    *************************/
    export_PSK();
    wait_for_file("../encrypted_challenge.txt");
    parse_challenge();
    /************************
    * END   [1. Communication between A_A & A_B]
    *************************/

    /************************
    * BEGIN [6&7. E_B decrypts the challenge, then computes and encrypts the response]
    *************************/
    solveChallenge(global_eid, &sgx_status, encrypted_challenge);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }
    /************************
    * END   6&7. E_B decrypts the challenge, then computes and encrypts the response]
    *************************/

    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("From App: Enclave destroyed.\n");
    return 0;
}

