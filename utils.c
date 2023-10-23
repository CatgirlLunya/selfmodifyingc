#include "utils.h"

dynarr_t base_func_addresses;
dynarr_t new_func_addresses;

typedef void(*vf)();

// DUMMY SPACE
// Allocates 32 bytes on the stack, puts rdi into first part of stack
void empty_function(unsigned long current_address) {
    unsigned long index = index_of(base_func_addresses, current_address);
    vf new_fp = (vf)new_func_addresses.mem[index];
    new_fp();
}

unsigned char bytes_to_copy_to_empty[] = {
    0xF3, 0x0F, 0x1E, 0xFA, //endbr64
    0x59, // pop rcx, gets rip
    0x55, // push rbp
    0x48, 0x89, 0xE5, // mov rbp, rsp
    0x48, 0x83, 0xE9, 0x09, // sub rcx, 9
    0x48, 0x89, 0xCF, // mov rdi, rcx
    0xFF, 0x35, 0x75, 0x2C, 0x00, 0x00, // push base_func_addresses.cap(+16)
    0xFF, 0x35, 0x67, 0x2C, 0x00, 0x00, // push base_func_addresses.count(+8)
    0xFF, 0x35, 0x59, 0x2C, 0x00, 0x00, // push base_func_addresses.mem(+0)
    0xe8, 0x14, 0x08, 0x00, 0x00, // call index_of
    0x48, 0x8b, 0x15, 0xA2, 0x2C, 0x00, 0x00, // mov rdx, new_func_addresses
    0x48, 0xC1, 0xE0, 0x03, // shl rax, 3 ; multiply result of index_of by 8
    0x48, 0x01, 0xD0, // add rax, rdx
    0xFF, 0x10, // call rdx
    0x90, // nop
    0xC9, // leave
    0xC3, // ret
};

void write_int(unsigned char* ptr, unsigned long index, unsigned int num) {
    for (int i = 0; i < 4; i++) {
        ptr[index + i] = ((unsigned char*)&num)[i];
    }
}

void setup_lookup_tables() {
    base_func_addresses = create_dyn_arr(1);
    new_func_addresses = create_dyn_arr(1);

    unsigned int base_func_address_dist = (unsigned long) &base_func_addresses.cap - (unsigned long) empty_function - 22;
    for (int i = 0; i < 3; i++) {
        write_int(bytes_to_copy_to_empty, 18 + i*6, base_func_address_dist - i*14);
    }
    unsigned int index_of_dist = (unsigned long)index_of - (unsigned long)empty_function - 39;
    write_int(bytes_to_copy_to_empty, 35, index_of_dist);

    unsigned int new_func_address_dist = (unsigned long)&new_func_addresses.mem - (unsigned long)empty_function - 46;
    write_int(bytes_to_copy_to_empty, 42, new_func_address_dist);

    int page_size = getpagesize();
    void* func_page = empty_function - ((unsigned long)empty_function % page_size);
    mprotect(func_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(empty_function, bytes_to_copy_to_empty, sizeof(bytes_to_copy_to_empty));
}

void undo_lookup_tables() {
    free_arr(base_func_addresses);
    free_arr(new_func_addresses);
}

function_t claim_function(void* func) {
    // Changing the original function to be writable
    int page_size = getpagesize();
    void* func_page = func - ((unsigned long)func % page_size);
    mprotect(func_page, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);

    // Setting up new func object
    function_t f;
    f.original_handle = func;
    unsigned char* mem_func = func;
    f.size = 0;
    puts("Initialized func object");
    while (mem_func[f.size] != 0xC3 || mem_func[f.size-1] != 0x5D || mem_func[f.size-2] != 0x90)
        f.size++;
    f.size++;
    f.memory = mmap(f.original_handle, 4096, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (f.memory == MAP_FAILED) perror("FAILED TO MMAP\n");
    f.original = malloc(f.size);
    memcpy(f.memory, mem_func, f.size);
    memcpy(f.original, mem_func, f.size);

    // Putting function into lookup tables
    push_back(&base_func_addresses, (unsigned long)func);
    push_back(&new_func_addresses, (unsigned long)f.memory);

    long difference = ((long)empty_function - (long)func);
    int mf_index = 4;
    if (labs(difference) < (1L << 32)) {
        puts("Using 32 bit call");
        mem_func[mf_index++] = 0xE8;
    } else {
        fputs("Too big of a jump difference!", stderr);
        abort();
    }
    int int_diff = (int)difference - 9;
    for (int i = 0; i < 4; i++)
        mem_func[i + mf_index] = ((unsigned char*) &int_diff)[i];
    mf_index += 4;
    mem_func[mf_index++] = 0xC3;

    return f;
}

void release_function(function_t func) {
    mprotect(func.memory, func.size, PROT_NONE);
    munmap(func.memory, func.size);
    int page_size = getpagesize();
    func.original_handle -= ((unsigned long)func.original_handle % page_size);
    mprotect(func.original_handle, page_size, PROT_READ | PROT_WRITE | PROT_EXEC);
    memcpy(func.original_handle, func.original, func.size);
    mprotect(func.original_handle, page_size, PROT_READ | PROT_EXEC);
    free(func.original);
}

static unsigned char replace_lea_data[] = {
        0x48, 0x83, 0xED, 0x08, // sub rbp, 8
        0x48, 0xBD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rbp, abs_addr
        0x48, 0x8D, 0x45, 0x00, // lea rax, [rsp]
        0x48, 0x83, 0xC5, 0x08, // add rsp, 8
};

static unsigned char replace_call_data[] = {
        0x48, 0x83, 0xED, 0x08, // sub rsp, 8
        0x48, 0xBD, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // movabs rsp, abs_addr
        0xFF, 0xD5, // call rsp
        0x48, 0x83, 0xC5, 0x08, // add rsp, 8
};

static unsigned char* get_replacement_data(unsigned long abs_addr, unsigned char opcode, unsigned long* size) {
    unsigned char* addr_buf = (unsigned char*)&abs_addr;
    unsigned char* buf_to_write;
    switch (opcode) {
        case 0x8D:
        case 0x8B:
            buf_to_write = replace_lea_data;
            *size = sizeof(replace_lea_data);
            replace_lea_data[15] = opcode;
            break;
        case 0xE8:
            abs_addr -= 15;
            buf_to_write = replace_call_data;
            *size = sizeof(replace_call_data);
            break;
        default:
            puts("UNSUPPORTED REPLACEMENT");
    }
    for (int i = 0; i < 8; i++)
        buf_to_write[i + 6] = addr_buf[i];
    return buf_to_write;
}

void fix_function_addressing(function_t* func) {
    dynarr_t corrected = create_dyn_arr(0);
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    unsigned long offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, func->memory + offset, func->size - offset, &instruction, operands))) {
        if (instruction.attributes & ZYDIS_ATTRIB_IS_RELATIVE) {
            // Checks to make sure I haven't already corrected the relative address
            printf("Checking for Correction: %lx\n", (unsigned long)func->memory + offset);
            if (index_of(corrected, (unsigned long)func->memory + offset) != (unsigned long)-1) {
                offset += instruction.length;
                continue;
            }
            puts("No correction found!");
            ZyanU64 result;
            ZyanStatus status;
            ZydisDecodedOperand* operand;
            // TODO: Reimplement with for loop or at least add more options
            if (instruction.mnemonic == ZYDIS_MNEMONIC_MOV || instruction.mnemonic == ZYDIS_MNEMONIC_LEA) {
                operand = &operands[1];
            } else {
                operand = &operands[0];
            }

            // Calculates absolute address and prints out some debug info
            if (!ZYAN_SUCCESS((status = ZydisCalcAbsoluteAddress(&instruction, operand, (ZyanU64)func->original_handle + offset, &result)))) {
                puts("Failed to calculate absolute address!");
                printf("ERROR CODE: %x\n", status);
                offset += instruction.length;
            } else {
                printf("OPCODE:           0x%X\n", instruction.opcode);
                printf("Absolute Address: 0x%lX\n", result);
                printf("Correction:       0x%lX\n", (unsigned long)func->memory + offset + 14);
                push_back(&corrected, (unsigned long)func->memory + offset + 14);
            }

            // Allocates extra bytes in memory for the corrected instructions and moves everything after that forward
            // Also gets replacement data to fill in the allocated memory
            unsigned long size;
            unsigned char* replacement_data = get_replacement_data(result, instruction.opcode, &size);
            unsigned long mem_move_offset = size - instruction.length;
            memmove(func->memory + offset + size, func->memory + offset + instruction.length, func->size - offset); // Allocating extra bytes of space for new instruction
            memcpy(func->memory + offset, replacement_data, size);

            // Increase function size and repeat this instruction as it has changed
            offset -= instruction.length;
            func->size += mem_move_offset;
        }
        offset += instruction.length;
    }
    print_func(func->memory, func->size);
    free_arr(corrected);
}

void print_func(void* function, unsigned long size) {
    void* rt_addr = function;
    ZydisDecoder decoder;
    ZydisDecoderInit(&decoder, ZYDIS_MACHINE_MODE_LONG_64, ZYDIS_STACK_WIDTH_64);
    ZydisFormatter formatter;
    ZydisFormatterInit(&formatter, ZYDIS_FORMATTER_STYLE_INTEL);
    unsigned long offset = 0;
    ZydisDecodedInstruction instruction;
    ZydisDecodedOperand operands[ZYDIS_MAX_OPERAND_COUNT];
    while (ZYAN_SUCCESS(ZydisDecoderDecodeFull(&decoder, function + offset, size - offset, &instruction, operands))) {
        printf("RTA: %lx(%4lx)\t\t\t", (unsigned long)rt_addr, (unsigned long) rt_addr - (unsigned long)function);
        char buffer[256];
        ZydisFormatterFormatInstruction(&formatter, &instruction, operands, instruction.operand_count_visible,
                                        buffer, sizeof(buffer), (ZyanU64)rt_addr, ZYAN_NULL);
        puts(buffer);
        rt_addr += instruction.length;
        offset += instruction.length;
    }
}