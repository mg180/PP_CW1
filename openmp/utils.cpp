#include "utils.hpp"

bool compare_bytes(void *a, void *b, unsigned int size_bytes)
{
    // Fast function to check if two memory locations of variable length are identical
    unsigned char *first = reinterpret_cast<unsigned char *>(a);
    unsigned char *second = reinterpret_cast<unsigned char *>(b);

    for (unsigned int byte_num = 0; byte_num < size_bytes; byte_num ++) {
        if (first[byte_num] != second[byte_num]) {
            return false;
        }
    }

    return true;
}

void print_bytes(void *start, unsigned int size_bits, unsigned int length, int base)
{
    // Print a number of bytes at memory location in specified base

    if (size_bits == 8) {
        uint8_t *start_byte = static_cast<uint8_t*>(start);

        for (int cur = 0; cur < length; cur++) {
            cout << setw(2) << right << setfill('0') << hex << (int)(start_byte[cur]) << " ";
        }
    } else if (size_bits == 16) {
        uint16_t *start_byte = static_cast<uint16_t*>(start);

        for (int cur = 0; cur < length; cur++) {
            cout << setw(4) << right << setfill('0') << hex << (start_byte[cur]);
        }
    } else if (size_bits == 32) {
        uint32_t *start_byte = static_cast<uint32_t*>(start);

        for (int cur = 0; cur < length; cur++) {
            cout << setw(8) << right << setfill('0') << hex << (start_byte[cur]);
        }
    } else if (size_bits == 64) {
        uint64_t *start_byte = static_cast<uint64_t*>(start);

        for (int cur = 0; cur < length; cur++) {
            cout << setw(16) << right << setfill('0') << hex << (start_byte[cur]);
        }
    }

    if (base == 16) {
        
    }
}

