#include <iostream>
#include <mpi.h>
#include <unistd.h>

#include "encrypt_aes_128_cbc.hpp"

main(int argc, char *argv[])
{
    // Initialise encryption class
    encrypt_aes_128_cbc key_search = encrypt_aes_128_cbc();

    // Known correct ciphertext used for comparison
    unsigned char ciphertext[16] = {0xd6, 0x54, 0x6e, 0x4c, 0x8b, 0xa8, 0x75, 0x1e, 0x58, 0x6c, 0x37, 0x43, 0xf5, 0x21, 0xef, 0x39};
    
    // Set the key to start searching at
    // The correct key is 0x23 23 23 23 23 73 61 6d 70 6c 65 23 23 23 23 23;
    unsigned char starting_key[16] = {0x23, 0x23, 0x23, 0x23, 0x23, 0x73, 0x61, 0x6d, 0x00, 0x00, 0x00, 0x00, 0x23, 0x23, 0x23, 0x23};

    // Set the IV used for each encryption test (this will never change)
    unsigned char iv[16] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x00, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f};

    // The plaintext that was used to generate the known ciphertext
    unsigned char plaintext[21] = {0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 0x61, 0x20, 0x74, 0x6f, 0x70, 0x20, 0x73, 0x65, 0x63, 0x72, 0x65, 0x74, 0x2e};

    key_search.initialise(plaintext, ciphertext, iv, starting_key);

    // Use a mask to only search a set portion of the key
    key_search.set_key_mask(0x00f0);

    
    int nodes, node;

    MPI_Init(&argc, &argv);
    MPI_Comm_rank(MPI_COMM_WORLD, &node);
    MPI_Comm_size(MPI_COMM_WORLD, &nodes );

    if (node == 0) {
        cout << "Distributed search mode (" << nodes << " nodes)..." << endl << endl;
    }

    sleep(1);
    
    cout << "Node " << node << " ready" << endl;

    sleep(1);

    if (node == 0) {
        key_search.search_distributed_master(nodes, node);
    } else {
        key_search.search_distributed_slave(nodes, node);
    }

    MPI_Finalize();
}
