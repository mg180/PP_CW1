Compile using:

mpic++ -std=c++11 -g *.cpp *.hpp -lcrypto -o aes-mpi

Run using:

mpirun -np <number_of_nodes> ./aes-mpi