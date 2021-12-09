# Clean traces
echo $'\n'CLEANING$'\n'
rm trace_A.out;
rm trace_B.out;

# Compile everything
echo $'\n'COMPILATION$'\n'
cd Enclave_A; make clean; make SGX_MODE=SIM;
cd ../Enclave_B; make clean; make SGX_MODE=SIM;
cd ..;

# Try several times
echo $'\n'TESTING$'\n'
numberTries=20
counter=1
while [ $counter -le $numberTries ]
do
    # Jump lines for readable traces
    echo $'\n'$counter :$'\n' >> trace_A.out
    echo $'\n'$counter :$'\n' >> trace_B.out

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

    sleep 30
    
    echo $counter/$numberTries
    ((counter++))
done

# Results
echo $'\n'RESULTS$'\n'
echo Number of tries: $numberTries;
echo Number of successes: $(cat trace_A.out | grep -c "Result match!");
echo Number of fails:     $(cat trace_A.out | grep -c "Result doesn't match!");
echo Number of errors:    $(cat trace_A.out | grep -c "Error:");
echo Number of timeouts:  $(cat trace_A.out | grep -c "File not received");

echo $'\n'More informations in files 'trace_A.out' and 'trace_B.out'$'\n'