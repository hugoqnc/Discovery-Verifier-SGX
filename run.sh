# Clean traces
rm trace_A.out;
rm trace_B.out;

# Compile everything
cd Enclave_A; make clean; make SGX_MODE=SIM;
cd ../Enclave_B; make clean; make SGX_MODE=SIM;
cd ..;

# Try several times
numberTries=5
counter=1
while [ $counter -le $numberTries ]
do
    # Jump lines for readable traces
    echo \ >> trace_A.out
    echo \ >> trace_B.out
    echo $counter :$'\n' >> trace_A.out
    echo $counter :$'\n' >> trace_B.out

    # Clean files
    rm p_public_A;
    rm p_public_B; 
    rm encrypted_PSK_A; 
    rm encrypted_PSK_B; 
    rm encrypted_challenge; 
    rm encrypted_challenge_response; 

    # Start in 2 terminals
    cd Enclave_A; gnome-terminal -- bash -c "./app >> ../trace_A.out;";
    cd ../Enclave_B; gnome-terminal -- bash -c "./app >> ../trace_B.out;";
    cd ..;

    sleep 35
    
    echo $counter/$numberTries
    ((counter++))
done

# Results
echo Number of tries: $numberTries;
echo Number of successes: $(cat trace_A.out | grep -c "Result match!");
echo Number of errors: $(cat trace_A.out | grep -c Error);