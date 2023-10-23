#ifndef SELFMODIFYINGBEHAVIOR_DYNARR_H
#define SELFMODIFYINGBEHAVIOR_DYNARR_H

#include <malloc.h>

typedef struct dynarr {
    unsigned long* mem;
    unsigned long count;
    unsigned long cap;
} dynarr_t;

dynarr_t create_dyn_arr(unsigned long capacity);
dynarr_t push_back(dynarr_t* arr, unsigned long elem);
unsigned long index_of(dynarr_t arr, unsigned long elem);
dynarr_t free_arr(dynarr_t arr);

#endif //SELFMODIFYINGBEHAVIOR_DYNARR_H
