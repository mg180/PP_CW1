#if !defined(UTILS)
#define UTILS

#include <iostream>
#include <iomanip>

using namespace std;

bool compare_bytes(void *a, void *b, unsigned int size_bytes);
void print_bytes(void *start, unsigned int size_bits, unsigned int length, int base);

#endif // UTILS