#include <iostream>
#include <stdint.h>
#include <cstring>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <chrono>
#include "utils.hpp"

using namespace std;

class encrypt_aes_128_cbc
{
private:
    unsigned char *plaintext;
    unsigned char *ciphertext;
    unsigned char *iv;
    unsigned char *key;
    uint16_t key_mask; // Limit the search to specific parts of the 128-bit key
    unsigned char ascii_start = 0;
    unsigned char ascii_end = 255;

    unsigned int distributed_batch_size = 1000000;

    // Used as a lookup during key generation as it is faster than continually calling the pow function
    const uint16_t byte_pow[16] = {0x8000, 0x4000, 0x2000, 0x1000, 0x0800, 0x0400, 0x0200, 0x0100, 0x0080, 0x0040, 0x0020, 0x0010, 0x0008, 0x0004, 0x0002, 0x0001,};

    bool initialised = false;
    bool show_progress = true;

    bool validate_key();
    bool next_key();
    int encrypt_fast(unsigned char *key, unsigned char *input, unsigned int input_len, unsigned char *output); 
    void handleOpenSSLErrors(void);
    void print_search_update(uint64_t current_iteration, uint64_t avg_ms);
    void print_configuration();

public:
    encrypt_aes_128_cbc(/* args */);
    ~encrypt_aes_128_cbc();

    bool test_unprintable = false;  // If disabled, only test printable ascii characters (A-Z, a-z, 0-9, symbols)

    void initialise(
        unsigned char *new_plaintext,
        unsigned char *new_ciphertext,
        unsigned char *new_iv,
        unsigned char *new_key
    );
    int set_key_mask(uint16_t new_mask);

    int search_sequential();
};