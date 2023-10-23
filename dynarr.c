#include "dynarr.h"

dynarr_t create_dyn_arr(unsigned long capacity) {
    if (capacity == 0) capacity = 1;
    dynarr_t dynarr;
    dynarr.count = 0;
    dynarr.cap = capacity;
    dynarr.mem = calloc(capacity, sizeof(unsigned long));
    return dynarr;
}

dynarr_t push_back(dynarr_t* arr, unsigned long elem) {
    if (arr->cap == arr->count) {
        arr->cap *= arr->cap;
        arr->mem = realloc(arr->mem, arr->cap);
    }
    arr->mem[arr->count++] = elem;
}

unsigned long index_of(dynarr_t arr, unsigned long elem) {
    for (unsigned long i = 0; i < arr.count; i++) {
        if (arr.mem[i] == elem) return i;
    }
    return -1;
}

dynarr_t free_arr(dynarr_t arr) {
    free(arr.mem);
}