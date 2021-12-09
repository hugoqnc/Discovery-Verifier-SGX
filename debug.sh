# Clean traces
rm trace_A.out;

# Compile everything
cd Enclave_A; make clean; make SGX_MODE=SIM;
cd ..;

# Try several times
numberTries=50
counter=1
while [ $counter -le $numberTries ]
do
    # Start in 1 terminal
    cd Enclave_A;./app >> ../trace_A.out;cd ..;

    # Jump lines for readable traces


    #sleep 1
    echo $counter/$numberTries
    ((counter++))
done

# Results
echo Number of tries: $numberTries;
echo Number of successes: $(cat trace_A.out | grep -c "Match!");
echo Number of errors: $(cat trace_A.out | grep -c "Error:");