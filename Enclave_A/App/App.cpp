#include <stdio.h>
#include <string.h>
#include <assert.h>

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>

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
    //printf("KEY: %s | %s\n",p_public_A.gx,p_public_A.gy);
    
    // Based on https://stackoverflow.com/questions/3811328/try-to-write-char-to-a-text-file/3811367

    remove("../p_public_A.txt");

    // Create and open a text file
    std::ofstream newFile("../p_public_A.txt");

    // Write to the file
    newFile.write((char*)::p_public_A.gx, SGX_ECP256_KEY_SIZE);
    newFile.write((char*)::p_public_A.gy, SGX_ECP256_KEY_SIZE);

    // Close the file
    newFile.close();

    // RECEIVE
    sgx_ec256_public_t p_public_A_receive;

    std::ifstream in("../p_public_A.txt");
    in.read((char*)p_public_A_receive.gx, SGX_ECP256_KEY_SIZE);
    in.read((char*)p_public_A_receive.gy, SGX_ECP256_KEY_SIZE);
    in.close();
    // printf("KEY: %s | %s\n",p_public_A_receive.gx,p_public_A_receive.gy);


    printf("From App: Exported p_public_A to filesystem\n");
}
// void export_public_key(){
//     printf("KEY: %s | %s\n", (char*)::p_public_A.gx, (char*)::p_public_A.gy);
    
//     // Based on https://stackoverflow.com/questions/3811328/try-to-write-char-to-a-text-file/3811367

//     remove("../p_public_A.txt");

//     // Create and open a text file
//     std::ofstream newFile("../p_public_A.txt");

//     // Write to the file
//     newFile.write((char*)::p_public_A.gx, SGX_ECP256_KEY_SIZE+1);
//     newFile.write((char*)::p_public_A.gy, SGX_ECP256_KEY_SIZE+1);

//     // Close the file
//     newFile.close();

//     // CODE
//     std::stringstream ss;
//     ss << std::hex << std::setfill('0');
//     for (int i = 0; i < SGX_ECP256_KEY_SIZE; ++i)
//     {
//         ss << std::setw(2) << static_cast<unsigned>(p_public_A.gx[i]);
//     }
//     std::string test = ss.str();
//     std::cout << "CODE: " << test << "\n";

//     //DECODE
//     std::istringstream hex_chars_stream(test);
//     uint8_t out_gx[SGX_ECP256_KEY_SIZE]; 

//     for (int b = 0, e = SGX_ECP256_KEY_SIZE; b < e; b += 2)
//     {
//         std::stringstream ss1;
//         ss1 << std::hex << test.substr(b, 2);

//         int valor;
//         ss1 >> valor;

//         out_gx[b / 2] = (unsigned char)valor;
//     }
//     // 
//     // std::vector<unsigned char> bytes;

//     // unsigned int c;
//     // while (hex_chars_stream >> std::hex >> c)
//     // {
//     //     bytes.push_back(c);
//     // }

//     printf("DECODE: %s \n", out_gx);


//     printf("From App: Exported p_public_A to filesystem\n");
// void export_public_key(){
//     printf("KEY: %s | %s\n",p_public_A.gx,p_public_A.gy);
    
//     // Based on https://stackoverflow.com/questions/3811328/try-to-write-char-to-a-text-file/3811367

//     remove("../p_public_A.txt");

//     // Create and open a text file
//     std::ofstream newFile("../p_public_A.txt");

//     // Write to the file
//     for (int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
//     {
//         newFile << p_public_A.gx[i];
//     }

//     for (int i = 0; i < SGX_ECP256_KEY_SIZE; i++)
//     {
//         newFile << p_public_A.gy[i];
//     }

//     // Close the file
//     newFile.close();

//     // RECEIVE
//     sgx_ec256_public_t p_public_A_receive;

//     std::ifstream in("../p_public_A.txt");
//     in.read((char*)p_public_A_receive.gx, SGX_ECP256_KEY_SIZE);
//     in.read((char*)p_public_A_receive.gy, SGX_ECP256_KEY_SIZE);
//     in.close();
//     printf("KEY: %s | %s\n",p_public_A_receive.gx,p_public_A_receive.gy);

    //bool equal = (std::strcmp(charTime, buf) == 0);


// }
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


