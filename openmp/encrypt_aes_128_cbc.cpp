#include "encrypt_aes_128_cbc.hpp"

encrypt_aes_128_cbc::encrypt_aes_128_cbc()
{
}

encrypt_aes_128_cbc::~encrypt_aes_128_cbc()
{
}

void encrypt_aes_128_cbc::print_configuration()
{
    // Print the starting values to ensure each test is consistent
    int l_width = 15;

    cout << setw(l_width) << left << setfill(' ') << "Plaintext:";
    print_bytes(plaintext, 8, 16, 16);
    cout << endl;

    cout << setw(l_width) << left << setfill(' ') << "Ciphertext:";
    print_bytes(ciphertext, 8, 16, 16);
    cout << endl;

    cout << setw(l_width) << left << setfill(' ') << "Starting Key:";
    print_bytes(key, 8, 16, 16);
    cout << endl;

    cout << setw(l_width) << left << setfill(' ') << "IV:";
    print_bytes(iv, 8, 16, 16);
    cout << endl;

    cout << setw(l_width) << left << setfill(' ') << "Key Mask:";
    print_bytes(reinterpret_cast<void *>(&key_mask), 16, 1, 16);
    cout << endl;
}

void encrypt_aes_128_cbc::initialise(
    unsigned char *new_plaintext,
    unsigned char *new_ciphertext,
    unsigned char *new_iv,
    unsigned char *new_key
) 
{
    plaintext = new_plaintext;
    ciphertext = new_ciphertext;
    iv = new_iv;
    key = new_key;

    if (test_unprintable == false) {
        ascii_start = 32;
        ascii_end = 126;
    }

    initialised = true;
}

int encrypt_aes_128_cbc::set_key_mask(uint16_t new_mask)
{
    key_mask = new_mask;
}

bool encrypt_aes_128_cbc::validate_key() {
    // Ensure that the current key does not contain any illegal values
    // E.g. if the character set is limited to printable ascii characters, ensure no
    // unprintable characters are present. If they are, set them to the next printable values
    for (int byte = 15; byte >= 0; byte--) {
        if (key[byte] < ascii_start) {
            cout << "Invalid Key - Value in byte " << dec << byte << " (" ;
            print_bytes(&(key[byte]), 8, 1, 16);
            cout << ") is smaller than minimum ascii value(" << hex << (int)ascii_start << "), setting to minimum value so we can continue" << endl;
            key[byte] = ascii_start;
        }
        if (key[byte] > ascii_end) {
            cout << "Invalid Key - Value in byte " << dec << byte << " (" ;
            print_bytes(&(key[byte]), 8, 1, 16);
            cout << ") exceeds maximum ascii value(" << hex << (int)ascii_end << "), setting to maximum value so we can continue" << endl;
            key[byte] = ascii_end;
        }
    }

    return false;
}

uint64_t encrypt_aes_128_cbc::key_seq(unsigned char **keys, uint64_t length) {
    /* Generate n number of keys as a batch job */

    uint64_t num_keys = 0;

    for (uint64_t key_num = 0; key_num < length; key_num++) {
        // If we run out of keys before finishing, break early so the number of keys we actually generated can be returned
        if (next_key() == true) {
            break;
        }
        
        keys[key_num] = new unsigned char[16];
        memcpy(keys[key_num], key, 16);

        num_keys++;
        
    }

    return num_keys;
}

bool encrypt_aes_128_cbc::next_key()
{
    // Generate the next valid 128 bit key ensuring that no restricted ASCII values are present
    bool done = false;

    for (int byte = 15; byte >= 0; byte--) {
        // Check if mask allows byte to be modified
        if (byte_pow[byte] & key_mask) {

            if (key[byte] == ascii_end) {
                // Set to the first valid ascii character overflow to next byte
                key[byte] = ascii_start;
            } else {
                key[byte]++;
                done = true;
                break;
            }
        }
    }

    if (done == false) {
        return true;
    } else {
        return false;
    }
   
}

int encrypt_aes_128_cbc::search_parallel(int num_mp_threads)
{   
    if (initialised == true) {
        print_configuration();  
        cout << endl;   

        uint64_t keys_searched = 0; // Keep track of how many keys have been searched to derive the keys searched per second
        unsigned char correct_key[16];
        bool key_found = false; // Used to break out of the main loop when the key is found
        bool keys_exhausted = false; // Usedd to break out of the main loop when all available key combinations have been exhausted
        chrono::high_resolution_clock::time_point t1 = chrono::high_resolution_clock::now();
        if (validate_key() == false) {
            cout << endl;
            while (key_found == false && keys_exhausted == false) {
                unsigned char *key_set[1000000];

                // Generate a new batch of keys
                uint64_t num_keys = key_seq(key_set, 1000000);
                if (num_keys < 1000000) {
                    keys_exhausted = true;
                }
                keys_searched += num_keys;

                chrono::high_resolution_clock::time_point avg_timer = chrono::high_resolution_clock::now();
                #pragma omp parallel num_threads(num_mp_threads)
                #pragma omp for
                for (uint64_t current_key = 0; current_key < num_keys; current_key++) {
                    unsigned char encrypted[32];
                    int encrypted_len = encrypt_fast(key_set[current_key], plaintext, 21, encrypted);

                    if (compare_bytes(encrypted, ciphertext, 16) == true) {
                        key_found = true;
                        memcpy(correct_key, key_set[current_key], 16);
                    }

                    free(key_set[current_key]);
                }
            }
        }
        chrono::high_resolution_clock::time_point t2 = chrono::high_resolution_clock::now();
        auto time_taken = chrono::duration_cast<chrono::milliseconds>(t2-t1).count();
        cout << "Time taken to complete search: " << dec << time_taken << "ms" << endl;
        double keys_per_sec = (keys_searched / time_taken) * 1000;
        cout << "Keys per second (avg): " << (uint64_t)keys_per_sec << endl;

        if (key_found == true) {
            cout << "Key found after searching " << dec << keys_searched <<  " iterations" <<endl;
            cout << "Correct key is: ";
            print_bytes(correct_key, 8, 16, 16);
            cout << endl;
        } else {
            cout << "Key could not be found within the specified search area - Try adjusting the mask to allow different keys to be searched" << endl;
        }      

    } else {
        cout << "Class is not initialised" << endl;
        return 1;
    }

    return 0;
}

int encrypt_aes_128_cbc::encrypt_fast(unsigned char *key, unsigned char *input, unsigned int input_len, unsigned char *output) 
{
    EVP_CIPHER_CTX *ctx;
    int len;
    int output_len;

    if(!(ctx = EVP_CIPHER_CTX_new())) handleOpenSSLErrors();

    if(1 != EVP_EncryptInit_ex(
        ctx, 
        EVP_aes_128_cbc(), 
        NULL, 
        key,
        iv
    ))
    {
        handleOpenSSLErrors();
    }

    if(1 != EVP_EncryptUpdate(
        ctx, 
        output, 
        &len, 
        plaintext,
        input_len
    ))
    {
        handleOpenSSLErrors();
    }
    output_len = len;

    if(1 != EVP_EncryptFinal_ex(
        ctx, 
        output + len, 
        &len
    )) {
        handleOpenSSLErrors();
    }
    output_len += len;

    EVP_CIPHER_CTX_free(ctx);

    return output_len;
}

void encrypt_aes_128_cbc::handleOpenSSLErrors(void) 
{
  ERR_print_errors_fp(stderr);
  abort();
}

void encrypt_aes_128_cbc::print_search_update(uint64_t current_iteration, uint64_t avg_ms) {
    cout << "\r" << "Iteration: " << dec << current_iteration;
    cout << "   Key: ";
    print_bytes(key, 8, 16, 16);
    cout << "  Average per 5M iterations: " << dec << avg_ms << "ms";
}