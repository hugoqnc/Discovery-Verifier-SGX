# Intel SGX Enclave Application

## Instructions
In the folder `EnclaveProtocol`, run the script `run.sh`.
This will first clean eventual files that are used for communication between the two applications.
It will then compile both SGX applications. Then, it will run the challenge 20 times,
and will finally display results, separated into four catgeories:
executions with successful and failed challenges, executions with errors and timeouts.
Details of the executions are provided in the files `trace_A.out` and `trace_B.out`.
The time of execution is of 30 seconds per challenge, so about 10 minutes with the default 
number of 20 challenges.

## Communication between the two applications
### Files
The following files are used for communication between the two applications,
and can appear in the `EnclaveProtocol` folder: 
* `p_public_A`
* `p_public_B`
* `encrypted_PSK_B`
* `encrypted_PSK_A`
* `encrypted_challenge`
* `encrypted_challenge_response`
  
They should not be modified, and will be cleaned up automatically using the `run.sh` script.
Otherwise, for manual testing, they also can be removed with the script `clean.sh`
(that will also remove execution traces `trace_A.out` and `trace_B.out`).

### Assumptions
The file communication uses some assumptions that led me to hardcode some values.
The most important is that the PSK should have a **length of 10 characters**.
The communication will not work properly otherwise.

Moreover, the integers chosen
for the challenge should be `uint32_t`, meaning that they should be integers storable on 
four bytes.

### Encryption
I wasn't able to make the given functions *sgx_aes_ctr_encrypt* and *sgx_aes_ctr_decrypt*
work reliably.
After a lot of time trying to make it work, I finally chose to use *sgx_rijndael128GCM_encrypt* and *sgx_rijndael128GCM_decrypt*
based on this [code](https://github.com/rodolfoams/sgx-aes-gcm). 

## Modifications
If necessary, some modifications can be made:
* For debugging purposes, some additional traces — that can violate the enclave confidentiality —
  can be displayed by setting the boolean `verbose_debug` to true,
  at the beginning of the files `App.cpp` and `Enclave.cpp` in both folders `Enclave_A` and `Enclave_B`.
* If the `run.sh` script indicates a lot of timeouts, the variable `timeoutFileReception` 
  can be modified (in seconds) at the beginning of the file `App.cpp` 
  in both folders `Enclave_A` and `Enclave_B`.
* If the `run.sh` script indicates some errors, and the traces are inconsistent, it may be due to
  the timeout assumption in the `run.sh` script. By default, the challenge is supposed to be
  completed under 30 seconds. It has always been the case in my testing, but if it not your case,
  you can modify this line 35 of `run.sh`. 
