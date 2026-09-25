/* Local-process runner for PeBinForge raw x64 payloads. */

#define WIN32_LEAN_AND_MEAN
#define _CRT_SECURE_NO_WARNINGS

#include <windows.h>
#include <wincrypt.h>
#include <errno.h>
#include <inttypes.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "pbf_abi.h"

#define MAX_PAYLOAD_SIZE (1024U * 1024U)
#define SHA256_SIZE 32U

static void usage(void) {
    puts("pbf-runner 0.3.0\n"
         "Usage: pbf-runner <payload.bin> [input-a] [input-b]\n"
         "                  [--entry context|noargs] [--inject-pid <pid>]\n\n"
         "The default ABI is entry(&context). The noargs ABI calls entry() and\n"
         "does not require a return value. --inject-pid executes it in an existing\n"
         "x64 process using remote RW -> RX memory and a remote thread.");
}

static int hex_value(int character) {
    if (character >= '0' && character <= '9') return character - '0';
    if (character >= 'a' && character <= 'f') return character - 'a' + 10;
    if (character >= 'A' && character <= 'F') return character - 'A' + 10;
    return -1;
}

static int read_expected_hash(const char *bin_path, BYTE expected[SHA256_SIZE]) {
    char sidecar[MAX_PATH];
    char text[65];
    FILE *file;
    size_t length = strlen(bin_path);
    unsigned int i;

    if (length + 8 >= sizeof(sidecar)) return 0;
    memcpy(sidecar, bin_path, length + 1);
    strcat(sidecar, ".sha256");
    file = fopen(sidecar, "rb");
    if (file == NULL || fread(text, 1, 64, file) != 64) {
        if (file != NULL) fclose(file);
        fprintf(stderr, "[-] Missing or invalid SHA-256 sidecar: %s\n", sidecar);
        return 0;
    }
    fclose(file);
    text[64] = 0;
    for (i = 0; i < SHA256_SIZE; ++i) {
        int high = hex_value(text[i * 2]);
        int low = hex_value(text[i * 2 + 1]);
        if (high < 0 || low < 0) return 0;
        expected[i] = (BYTE)((high << 4) | low);
    }
    return 1;
}

static int hash_bytes(const BYTE *data, DWORD length, BYTE digest[SHA256_SIZE]) {
    HCRYPTPROV provider = 0;
    HCRYPTHASH hash = 0;
    DWORD digest_size = SHA256_SIZE;
    int ok = 0;

    if (!CryptAcquireContextA(&provider, NULL, NULL, PROV_RSA_AES,
                              CRYPT_VERIFYCONTEXT | CRYPT_SILENT)) {
        goto cleanup;
    }
    if (!CryptCreateHash(provider, CALG_SHA_256, 0, 0, &hash)) goto cleanup;
    if (!CryptHashData(hash, data, length, 0)) goto cleanup;
    if (!CryptGetHashParam(hash, HP_HASHVAL, digest, &digest_size, 0) ||
        digest_size != SHA256_SIZE) {
        goto cleanup;
    }
    ok = 1;

cleanup:
    if (hash != 0) CryptDestroyHash(hash);
    if (provider != 0) CryptReleaseContext(provider, 0);
    return ok;
}

static int parse_u64(const char *text, uint64_t *value) {
    char *end = NULL;
    unsigned long long parsed;
    errno = 0;
    parsed = _strtoui64(text, &end, 0);
    if (errno != 0 || end == text || *end != 0) return 0;
    *value = (uint64_t)parsed;
    return 1;
}

static void print_proof(const uint8_t proof[16]) {
    unsigned int i;
    for (i = 0; i < 16; ++i) printf("%02x", proof[i]);
}

static int run_remote(DWORD target_pid, const BYTE *payload, SIZE_T payload_size,
                      pbf_context *context, int noargs_entry) {
    const DWORD access = PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | SYNCHRONIZE;
    HANDLE process = NULL;
    HANDLE thread = NULL;
    BYTE *remote_payload = NULL;
    pbf_context *remote_context = NULL;
    SIZE_T transferred = 0;
    DWORD old_protection = 0;
    DWORD thread_exit = 0;
    DWORD wait_result;
    BOOL current_wow64 = FALSE;
    BOOL target_wow64 = FALSE;
    int thread_finished = 0;
    int result = 6;

    if (target_pid == 0 || target_pid == GetCurrentProcessId()) {
        fputs("[-] --inject-pid must name a different process.\n", stderr);
        return 2;
    }
    process = OpenProcess(access, FALSE, target_pid);
    if (process == NULL) {
        fprintf(stderr, "[-] OpenProcess(%lu) failed: %lu\n",
            target_pid, GetLastError());
        goto cleanup;
    }
    if (!IsWow64Process(GetCurrentProcess(), &current_wow64) ||
        !IsWow64Process(process, &target_wow64) ||
        current_wow64 != target_wow64) {
        fputs("[-] Target process architecture is incompatible with this runner.\n", stderr);
        goto cleanup;
    }

    remote_payload = (BYTE *)VirtualAllocEx(process, NULL, payload_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (remote_payload == NULL ||
        !WriteProcessMemory(process, remote_payload, payload, payload_size,
                            &transferred) || transferred != payload_size) {
        fprintf(stderr, "[-] Unable to write remote payload memory: %lu\n",
            GetLastError());
        goto cleanup;
    }
    if (!noargs_entry) {
        remote_context = (pbf_context *)VirtualAllocEx(process, NULL,
            sizeof(*context), MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
        if (remote_context == NULL ||
            !WriteProcessMemory(process, remote_context, context, sizeof(*context),
                                &transferred) || transferred != sizeof(*context)) {
            fprintf(stderr, "[-] Unable to write remote payload context: %lu\n",
                GetLastError());
            goto cleanup;
        }
    }
    if (!VirtualProtectEx(process, remote_payload, payload_size,
                          PAGE_EXECUTE_READ, &old_protection) ||
        !FlushInstructionCache(process, remote_payload, payload_size)) {
        fprintf(stderr, "[-] Unable to finalize remote RX memory: %lu\n",
            GetLastError());
        goto cleanup;
    }

    thread = CreateRemoteThread(process, NULL, 0,
        (LPTHREAD_START_ROUTINE)(ULONG_PTR)remote_payload,
        noargs_entry ? NULL : remote_context, 0, NULL);
    if (thread == NULL) {
        fprintf(stderr, "[-] CreateRemoteThread failed: %lu\n", GetLastError());
        goto cleanup;
    }
    wait_result = WaitForSingleObject(thread, INFINITE);
    if (wait_result != WAIT_OBJECT_0) {
        fprintf(stderr, "[-] Waiting for the remote thread failed: %lu\n",
            wait_result == WAIT_FAILED ? GetLastError() : wait_result);
        goto cleanup;
    }
    thread_finished = 1;
    if (!GetExitCodeThread(thread, &thread_exit)) {
        fprintf(stderr, "[-] Unable to read remote thread status: %lu\n",
            GetLastError());
        goto cleanup;
    }

    printf("[+] SHA-256 verified; PID %lu memory transitioned RW -> RX.\n",
        target_pid);
    if (noargs_entry) {
        printf("[+] Standalone entry() completed in remote PID %lu.\n", target_pid);
    } else {
        if ((uint64_t)thread_exit != (PBF_RESULT_OK & UINT64_C(0xffffffff))) {
            fprintf(stderr, "[-] Remote context entry returned 0x%08lx instead of the ABI result.\n",
                thread_exit);
            goto cleanup;
        }
        if (!ReadProcessMemory(process, remote_context, context, sizeof(*context),
                               &transferred) || transferred != sizeof(*context)) {
            fprintf(stderr, "[-] Unable to read the completed remote context: %lu\n",
                GetLastError());
            goto cleanup;
        }
        printf("[+] Remote payload result: 0x%016" PRIx64 "\n", context->result);
        printf("[+] Remote proof: ");
        print_proof(context->proof);
        putchar('\n');
    }
    result = 0;

cleanup:
    if (thread != NULL) CloseHandle(thread);
    if (process != NULL && thread_finished) {
        if (remote_context != NULL) VirtualFreeEx(process, remote_context, 0, MEM_RELEASE);
        if (remote_payload != NULL) VirtualFreeEx(process, remote_payload, 0, MEM_RELEASE);
    } else if (process != NULL && thread == NULL) {
        if (remote_context != NULL) VirtualFreeEx(process, remote_context, 0, MEM_RELEASE);
        if (remote_payload != NULL) VirtualFreeEx(process, remote_payload, 0, MEM_RELEASE);
    }
    if (process != NULL) CloseHandle(process);
    return result;
}

int main(int argc, char **argv) {
    const char *path;
    const char *numeric_arguments[2];
    struct _stat64 status;
    FILE *file = NULL;
    BYTE *file_data = NULL;
    BYTE *executable = NULL;
    BYTE expected_hash[SHA256_SIZE];
    BYTE actual_hash[SHA256_SIZE];
    pbf_context context;
    pbf_entry_fn entry;
    pbf_standalone_entry_fn standalone_entry;
    uint64_t call_result = 0;
    DWORD old_protection = 0;
    int noargs_entry = 0;
    int entry_seen = 0;
    DWORD inject_pid = 0;
    int inject_seen = 0;
    int numeric_count = 0;
    int index;
    int exit_code = 1;

    if (argc == 2 && (strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0)) {
        usage();
        return 0;
    }
    if (argc < 2) {
        usage();
        return 2;
    }
    path = argv[1];
    for (index = 2; index < argc; ++index) {
        if (strcmp(argv[index], "--entry") == 0) {
            if (entry_seen || ++index >= argc) return 2;
            entry_seen = 1;
            if (strcmp(argv[index], "context") == 0) noargs_entry = 0;
            else if (strcmp(argv[index], "noargs") == 0) noargs_entry = 1;
            else {
                fputs("[-] --entry must be context or noargs.\n", stderr);
                return 2;
            }
        } else if (strcmp(argv[index], "--inject-pid") == 0) {
            uint64_t parsed_pid;
            if (inject_seen || ++index >= argc ||
                !parse_u64(argv[index], &parsed_pid) ||
                parsed_pid == 0 || parsed_pid > MAXDWORD) {
                fputs("[-] --inject-pid requires a valid nonzero process ID.\n", stderr);
                return 2;
            }
            inject_seen = 1;
            inject_pid = (DWORD)parsed_pid;
        } else {
            if (numeric_count >= 2) return 2;
            numeric_arguments[numeric_count++] = argv[index];
        }
    }
    if (noargs_entry && numeric_count != 0) {
        fputs("[-] The noargs entry ABI does not accept numeric payload inputs.\n", stderr);
        return 2;
    }

    memset(&context, 0, sizeof(context));
    context.size = sizeof(context);
    context.abi_version = PBF_ABI_VERSION;
    context.input_a = 21;
    context.input_b = 21;
    if (numeric_count >= 1 && !parse_u64(numeric_arguments[0], &context.input_a)) {
        fputs("[-] input-a is not a valid unsigned integer.\n", stderr);
        return 2;
    }
    if (numeric_count >= 2 && !parse_u64(numeric_arguments[1], &context.input_b)) {
        fputs("[-] input-b is not a valid unsigned integer.\n", stderr);
        return 2;
    }

    if (_stat64(path, &status) != 0 || status.st_size <= 0 ||
        status.st_size > MAX_PAYLOAD_SIZE) {
        fputs("[-] Payload is missing, empty, or exceeds 1 MiB.\n", stderr);
        return 3;
    }
    if (!read_expected_hash(path, expected_hash)) return 3;
    file_data = (BYTE *)malloc((size_t)status.st_size);
    file = fopen(path, "rb");
    if (file_data == NULL || file == NULL ||
        fread(file_data, 1, (size_t)status.st_size, file) != (size_t)status.st_size) {
        fputs("[-] Unable to read payload.\n", stderr);
        goto cleanup;
    }
    fclose(file);
    file = NULL;
    if (!hash_bytes(file_data, (DWORD)status.st_size, actual_hash) ||
        memcmp(actual_hash, expected_hash, SHA256_SIZE) != 0) {
        fputs("[-] SHA-256 verification failed; payload was not executed.\n", stderr);
        exit_code = 4;
        goto cleanup;
    }

    if (inject_pid != 0) {
        exit_code = run_remote(inject_pid, file_data, (SIZE_T)status.st_size,
                               &context, noargs_entry);
        goto cleanup;
    }

    executable = (BYTE *)VirtualAlloc(NULL, (SIZE_T)status.st_size,
        MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
    if (executable == NULL) {
        fprintf(stderr, "[-] VirtualAlloc failed: %lu\n", GetLastError());
        goto cleanup;
    }
    memcpy(executable, file_data, (size_t)status.st_size);
    SecureZeroMemory(file_data, (SIZE_T)status.st_size);
    free(file_data);
    file_data = NULL;

    if (!VirtualProtect(executable, (SIZE_T)status.st_size,
                        PAGE_EXECUTE_READ, &old_protection) ||
        !FlushInstructionCache(GetCurrentProcess(), executable, (SIZE_T)status.st_size)) {
        fprintf(stderr, "[-] Unable to finalize RX memory: %lu\n", GetLastError());
        goto cleanup;
    }

    entry = (pbf_entry_fn)(void *)executable;
    standalone_entry = (pbf_standalone_entry_fn)(void *)executable;
    __try {
        if (noargs_entry) standalone_entry();
        else call_result = entry(&context);
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        fprintf(stderr, "[-] Payload raised exception 0x%08lx.\n", GetExceptionCode());
        exit_code = 5;
        goto cleanup;
    }
    if (!noargs_entry && call_result != PBF_RESULT_OK) {
        fprintf(stderr, "[-] Payload returned unexpected ABI result 0x%016" PRIx64 ".\n",
            call_result);
        exit_code = 5;
        goto cleanup;
    }

    printf("[+] SHA-256 verified; memory transitioned RW -> RX.\n");
    if (noargs_entry) {
        printf("[+] Standalone entry() completed in PID %lu.\n", GetCurrentProcessId());
    } else {
        printf("[+] Payload result: 0x%016" PRIx64 "\n", context.result);
        printf("[+] Proof: ");
        print_proof(context.proof);
        putchar('\n');
    }
    exit_code = 0;

cleanup:
    if (executable != NULL) VirtualFree(executable, 0, MEM_RELEASE);
    if (file != NULL) fclose(file);
    if (file_data != NULL) {
        SecureZeroMemory(file_data, (SIZE_T)status.st_size);
        free(file_data);
    }
    return exit_code;
}
