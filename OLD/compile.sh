../clean.sh;
cd Enclave_A; make clean; make SGX_MODE=SIM;
cd ../Enclave_B; make clean; make SGX_MODE=SIM;