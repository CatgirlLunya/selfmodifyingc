#ifndef SELFMODIFYINGBEHAVIOR_UTILS_H
#define SELFMODIFYINGBEHAVIOR_UTILS_H

#include "dynarr.h"

#include <string.h>
#include <unistd.h>
#include <stdio.h>
#include <malloc.h>
#include <stdlib.h>

#include <sys/mman.h>

#include <Zydis/Zydis.h>

typedef struct function {
    void* original_handle;
    unsigned char* original;
    unsigned char* memory;
    unsigned long size;
} function_t;

void setup_lookup_tables();
void undo_lookup_tables();

function_t claim_function(void* func);
void release_function(function_t func);

void fix_function_addressing(function_t* func);
void print_func(void* function, unsigned long size);

#endif //SELFMODIFYINGBEHAVIOR_UTILS_H
