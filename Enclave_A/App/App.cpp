#include <stdio.h>
#include <string.h>
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

/************************
* BEGIN [2. E_A key pair generation]
*************************/
void ocall_send_public_key(sgx_ec256_public_t p_public){
    p_public_A = p_public;
    printf("From App: Received p_public_A\n");
}
void export_public_key(){
    // Based on https://www.w3schools.com/cpp/cpp_files.asp

    remove("../p_public_A.txt");

    // Create and open a text file
    std::ofstream MyFile("../p_public_A.txt");

    // Write to the file
    MyFile << ::p_public_A.gx;
    MyFile << "\n";
    MyFile << ::p_public_A.gy;

    // Close the file
    MyFile.close();

    printf("From App: Exported p_public_A to filesystem\n");
}
/************************
* END   [2. E_A key pair generation]
*************************/


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
    printf("From App: Write your protocol here ... \n");


    sgx_status_t sgx_status;

    printSecret(global_eid, &sgx_status);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    /************************
    * BEGIN [2. E_A key pair generation]
    *************************/
    generateKeyPair(global_eid, &sgx_status);
    if (sgx_status != SGX_SUCCESS) {
        print_error_message(sgx_status);
        return -1;
    }

    export_public_key();
    /************************
    * END   [2. E_A key pair generation]
    *************************/


    /* Destroy the enclave */
    sgx_destroy_enclave(global_eid);

    printf("From App: Enclave destroyed.\n");
    return 0;
}


