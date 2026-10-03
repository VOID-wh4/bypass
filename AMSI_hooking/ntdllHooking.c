#define _WIN32_WINNT 0x0600
#include <stdio.h>
#include <windows.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>

#define DLL_BLOCK_LIST "amsi.dll"

/*
 * Hook after the currently installed Windows LdrLoadDll prologue.  This is an
 * instruction boundary; +30 is in the middle of the instruction at +28.
 */
#define LDR_HOOK_OFFSET 36u
static const BYTE g_expected_ldr_prefix[LDR_HOOK_OFFSET] = {
    0x4c,0x8b,0xdc,                         /* mov r11,rsp */
    0x49,0x89,0x5b,0x10,                   /* mov [r11+10h],rbx */
    0x56,0x57,0x41,0x56,                   /* push rsi/rdi/r14 */
    0x48,0x81,0xec,0xd0,0x00,0x00,0x00,   /* sub rsp,0d0h */
    0x48,0x8b,0x05,0x9f,0xd9,0x1a,0x00,   /* mov rax,[rip+...] */
    0x48,0x33,0xc4,                         /* xor rax,rsp */
    0x48,0x89,0x84,0x24,0xc0,0x00,0x00,0x00 /* mov [rsp+c0h],rax */
};

// 전역 변수 설정 (ANSI 기반)
char *g_dll_block_list = NULL;
LPVOID g_remote_ntdll_base = NULL;
LPVOID g_remote_ldr_addr = NULL;
BYTE g_orig_byte = 0;
HANDLE g_hProc = NULL;
DWORD  g_pending_rearm_tid = 0;

typedef struct _UNICODE_STRING_REMOTE {
    USHORT Length;
    USHORT MaximumLength;
    ULONGLONG Buffer;
} UNICODE_STRING_REMOTE;

// 원격 프로세스 메모리 읽기
static int read_remote(LPCVOID lpcAddr, void *vpBuf, SIZE_T sz) {
    SIZE_T n = 0; 
    return ReadProcessMemory(g_hProc, lpcAddr, vpBuf, sz, &n) && (n == sz);
}

// 원격 프로세스 메모리 쓰기
static int write_remote(LPVOID addr, const void *buf, SIZE_T sz) {
    SIZE_T n = 0; 
    return WriteProcessMemory(g_hProc, addr, buf, sz, &n) && (n == sz) && FlushInstructionCache(g_hProc, addr, sz);
}

// 실행 권한 변경 후 메모리 쓰기
static int write_code(LPVOID addr, const void *buf, SIZE_T sz) {
    DWORD oldProt = 0, tmp;
    if (!VirtualProtectEx(g_hProc, addr, sz, PAGE_READWRITE, &oldProt)) return 0;
    int ok = write_remote(addr, buf, sz);
    VirtualProtectEx(g_hProc, addr, sz, oldProt, &tmp);
    return ok;
}

// INT3(0xCC) 중단점 설정
static int set_int3(LPVOID addr, BYTE *saved_byte) {
    BYTE b;
    BYTE cc = 0xCC;
    if (!read_remote(addr, &b, 1)) return 0;
    *saved_byte = b;
    return write_code(addr, &cc, 1);
}

static int check_hook_status(void)
{
    if (!g_remote_ldr_addr) {
        return -1;
    }

    BYTE current_byte = 0;

    if (!read_remote(g_remote_ldr_addr, &current_byte, 1)) {
        wprintf(L"[HOOK] Failed to read LdrLoadDll byte\n");
        return -1;
    }

    if (current_byte == 0xCC) {
        // wprintf(
        //     L"[HOOK] ACTIVE   LdrLoadDll = 0x%02X\n",
        //     current_byte
        // );
        return 1;
    }

    if (current_byte == g_orig_byte) {
        wprintf(
            L"[HOOK] UNHOOKED LdrLoadDll = 0x%02X "
            L"(original = 0x%02X)\n",
            current_byte,
            g_orig_byte
        );
        return 0;
    }

    wprintf(
        L"[HOOK] CHANGED  LdrLoadDll = 0x%02X "
        L"(hook = 0xCC, original = 0x%02X)\n",
        current_byte,
        g_orig_byte
    );

    return 0;
}

// 경로에서 파일명 추출 (ANSI)
static const char *filename_of(const char *s) {
    if (!s) return s;
    const char *p1 = strrchr(s, '\\');
    const char *p2 = strrchr(s, '/');
    if (p1 && p2) return (p1 > p2) ? (p1 + 1) : (p2 + 1);
    if (p1) return p1 + 1;
    if (p2) return p2 + 1;
    return s;
}

// 대소문자 무시 문자열 비교 (ANSI)
static BOOL strncaseeq_seg(const char *a, const char *b, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        if (tolower((unsigned char)a[i]) != tolower((unsigned char)b[i])) return FALSE;
    }
    return TRUE;
}

// 공백 제거 (ANSI)
static const char *trim_bounds(const char *start, const char *end, size_t *out_len) {
    while (start < end && isspace((unsigned char)*start)) ++start;
    while (end > start && isspace((unsigned char)*(end - 1))) --end;
    *out_len = (size_t)(end - start);
    return start;
}

// 차단 목록에 DLL이 포함되어 있는지 확인 (ANSI)
BOOL dll_in_list_ci(const char *dll_or_path) {
    if (!dll_or_path || !g_dll_block_list) return FALSE;
    const char *fname = filename_of(dll_or_path);
    size_t fname_len = strlen(fname);
    if (fname_len == 0) return FALSE;

    const char *p = g_dll_block_list;
    while (*p) {
        const char *q = strchr(p, ',');
        const char *segment_end = q ? q : (p + strlen(p));
        size_t tok_len = 0;
        const char *tok = trim_bounds(p, segment_end, &tok_len);

        if (tok_len == fname_len && strncaseeq_seg(tok, fname, fname_len)) {
            return TRUE;
        }
        if (!q) break;
        p = q + 1;
    }
    return FALSE;
}

// 트랩 플래그 설정
static void set_tf_handling(HANDLE hThread, CONTEXT ctx, DWORD dwThreadID) {
    ctx.EFlags |= 0x100;
    SetThreadContext(hThread, &ctx);
    g_pending_rearm_tid = dwThreadID;
    CloseHandle(hThread);
}

// LdrLoadDll 호출 인터셉트 및 처리
static int handle_ldr_call(const DWORD dwThreadID) {
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, dwThreadID);
    if (!hThread) return 0;

    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_ALL;
    if (!GetThreadContext(hThread, &ctx)) { CloseHandle(hThread); return 0; }

    if ((LPVOID)((uintptr_t)ctx.Rip - 1) != g_remote_ldr_addr) { CloseHandle(hThread); return 0; }

    if (!write_code(g_remote_ldr_addr, &g_orig_byte, 1)) { CloseHandle(hThread); return 0; }
    ctx.Rip -= 1;

    const ULONGLONG ullDllName = ctx.R8;
    if (!ullDllName) {
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1; 
    }

    UNICODE_STRING_REMOTE us = {0};
    if (!(read_remote((LPCVOID)ullDllName, &us, sizeof(us)) && us.Buffer && us.Length)) {
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1;
    }

    size_t wcharCount = us.Length / sizeof(wchar_t);
    wchar_t *wc_dllName = (wchar_t*)HeapAlloc(GetProcessHeap(), 0, (wcharCount + 1) * sizeof(wchar_t));
    if (!wc_dllName) {
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1;
    }

    if (!read_remote((LPCVOID)us.Buffer, wc_dllName, wcharCount * sizeof(wchar_t))) {
        HeapFree(GetProcessHeap(), 0, wc_dllName);
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1;
    }
    wc_dllName[wcharCount] = L'\0';

    // LdrLoadDll은 항상 UNICODE를 사용하므로, 비교를 위해 ANSI(char)로 변환
    int ansi_len = WideCharToMultiByte(CP_ACP, 0, wc_dllName, -1, NULL, 0, NULL, NULL);
    char *c_dllName = (char*)HeapAlloc(GetProcessHeap(), 0, ansi_len);
    WideCharToMultiByte(CP_ACP, 0, wc_dllName, -1, c_dllName, ansi_len, NULL, NULL);

    if (!dll_in_list_ci(c_dllName)) {
        HeapFree(GetProcessHeap(), 0, wc_dllName);
        HeapFree(GetProcessHeap(), 0, c_dllName);
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1; 
    }

    const ULONGLONG pBase = ctx.R9;
    const ULONGLONG zero = 0;
    if (pBase) write_remote((LPVOID)(ULONG_PTR)pBase, &zero, sizeof(zero));

    ctx.Rax = 0xC0000135; 
    
    /*
     * At +36, LdrLoadDll has pushed rsi/rdi/r14 and reserved 0xd0 bytes.
     * Restore those nonvolatile registers and locate the caller's return
     * address before faking an unsuccessful return.
     */
    ULONGLONG saved_r14 = 0, saved_rdi = 0, saved_rsi = 0, retaddr = 0;
    ULONGLONG entry_rsp = ctx.Rsp + 0xe8;
    if (read_remote((LPCVOID)(ULONG_PTR)(ctx.Rsp + 0xd0), &saved_r14, sizeof(saved_r14)) &&
        read_remote((LPCVOID)(ULONG_PTR)(ctx.Rsp + 0xd8), &saved_rdi, sizeof(saved_rdi)) &&
        read_remote((LPCVOID)(ULONG_PTR)(ctx.Rsp + 0xe0), &saved_rsi, sizeof(saved_rsi)) &&
        read_remote((LPCVOID)(ULONG_PTR)entry_rsp, &retaddr, sizeof(retaddr))) {
        ctx.R14 = saved_r14;
        ctx.Rdi = saved_rdi;
        ctx.Rsi = saved_rsi;
        ctx.Rsp = entry_rsp + 8;
        ctx.Rip = retaddr;
    } else {
        HeapFree(GetProcessHeap(), 0, wc_dllName);
        HeapFree(GetProcessHeap(), 0, c_dllName);
        set_tf_handling(hThread, ctx, dwThreadID);
        return 1;
    }

    printf("[+] Blocked loading of '%s'\n", c_dllName);

    set_int3(g_remote_ldr_addr, &g_orig_byte);
    check_hook_status();
    SetThreadContext(hThread, &ctx);
    
    HeapFree(GetProcessHeap(), 0, wc_dllName);
    HeapFree(GetProcessHeap(), 0, c_dllName);
    CloseHandle(hThread);

    return 2; 
}

// Single Step 복구
static void rearm_after_single_step(const DEBUG_EVENT *de) {
    if (!g_remote_ldr_addr || de->dwThreadId != g_pending_rearm_tid) return;
    HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, de->dwThreadId);
    if (!hThread) return;
    
    CONTEXT ctx = {0};
    ctx.ContextFlags = CONTEXT_CONTROL;
    if (GetThreadContext(hThread, &ctx)) {
        ctx.EFlags &= ~0x100;
        SetThreadContext(hThread, &ctx);
    }
    
    set_int3(g_remote_ldr_addr, &g_orig_byte);
    check_hook_status();
    g_pending_rearm_tid = 0;
    CloseHandle(hThread);
}


int main(int argc, char **argv) {
    char *c_dlls = NULL;
    BOOL done = FALSE;
    DWORD child_exit_code = 0;

    if (argc < 2) {
        printf("Usage:\n%s \"<command with args>\" [DLLs to block]\n\n", argv[0]);
        printf("Default block list: %s\n", DLL_BLOCK_LIST);
        return 1;
    }

    c_dlls = (argc >= 3) ? argv[2] : DLL_BLOCK_LIST;
    g_dll_block_list = (char *)malloc(strlen(c_dlls) + 1);
    if (!g_dll_block_list) return 2;
    strcpy(g_dll_block_list, c_dlls);

    size_t cmdlen = strlen(argv[1]);
    char *cmdline = (char *)malloc(cmdlen + 1);
    if (!cmdline) {
        free(g_dll_block_list);
        return 3;
    }
    strcpy(cmdline, argv[1]);

    // CreateProcessA를 사용하도록 변경
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    printf("[*] Command: '%s'\n", cmdline);
    printf("[*] Blocked DLLs: '%s'\n", g_dll_block_list);

    if (!CreateProcessA(NULL, cmdline, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        printf("[!] CreateProcess failed: %lu\n", GetLastError());
        free(cmdline);
        free(g_dll_block_list);
        return 1;
    }

    printf("[+] Started process\n");
    g_hProc = pi.hProcess;
    DEBUG_EVENT debug_event = {0};

    while (!done) {
        if (!WaitForDebugEvent(&debug_event, INFINITE)) {
            printf("[!] WaitForDebugEvent failed: %lu\n", GetLastError());
            break;
        }

        DWORD cont = DBG_CONTINUE;

        switch (debug_event.dwDebugEventCode) {
            case LOAD_DLL_DEBUG_EVENT: {
                char path[MAX_PATH * 4] = {0};
                LPSTR lpsDllName = NULL;

                if (!g_remote_ntdll_base) {
                    if (debug_event.u.LoadDll.hFile) {
                        GetFinalPathNameByHandleA(debug_event.u.LoadDll.hFile, path, sizeof(path)/sizeof(path[0]), FILE_NAME_NORMALIZED);
                        if (path[0]) lpsDllName = (strrchr(path, '\\') + 1);
                        CloseHandle(debug_event.u.LoadDll.hFile);
                    }

                    if (lpsDllName && strcmp(lpsDllName, "ntdll.dll") == 0) {
                        g_remote_ntdll_base = debug_event.u.LoadDll.lpBaseOfDll;
                        HMODULE ntdll_local = GetModuleHandleA("ntdll.dll");
                        
                        if (ntdll_local && g_remote_ntdll_base) {
                            FARPROC ldr_local = GetProcAddress(ntdll_local, "LdrLoadDll");
                            uintptr_t offset = (uintptr_t)ldr_local - (uintptr_t)ntdll_local;
                            LPVOID remote_ldr_entry = (LPVOID)((BYTE*)g_remote_ntdll_base + offset);
                            BYTE remote_prefix[LDR_HOOK_OFFSET] = {0};
                            if (!read_remote(remote_ldr_entry, remote_prefix, sizeof(remote_prefix)) ||
                                memcmp(remote_prefix, g_expected_ldr_prefix, sizeof(remote_prefix)) != 0) {
                                fprintf(stderr,
                                    "[!] LdrLoadDll prologue mismatch; forcing hook at +%u\n",
                                    (unsigned)LDR_HOOK_OFFSET);
                            }
                            g_remote_ldr_addr = (LPVOID)((BYTE*)remote_ldr_entry + LDR_HOOK_OFFSET);

                            if (!set_int3(g_remote_ldr_addr, &g_orig_byte)) {
                                fprintf(stderr, "[!] Failed to install LdrLoadDll hook: %lu\n", GetLastError());
                                g_remote_ldr_addr = NULL;
                                break;
                            }
                            printf("[+] Hooked LdrLoadDll at 0x%p (ntdll at 0x%p)\n", g_remote_ldr_addr, g_remote_ntdll_base);
                            check_hook_status();
                        }
                    }
                }
                break;
            }

            case EXCEPTION_DEBUG_EVENT: {
                DWORD code = debug_event.u.Exception.ExceptionRecord.ExceptionCode;

                if (code == EXCEPTION_BREAKPOINT && g_remote_ldr_addr) {
                    int ret = handle_ldr_call(debug_event.dwThreadId);
                    if (ret == 2 || ret == 1) {
                        cont = DBG_CONTINUE;
                        break;
                    }
                }

                if (code == EXCEPTION_SINGLE_STEP && g_remote_ldr_addr) {
                    rearm_after_single_step(&debug_event);
                    cont = DBG_CONTINUE;
                    break;
                }

                if (code == EXCEPTION_BREAKPOINT) { cont = DBG_CONTINUE; break; }
                cont = DBG_EXCEPTION_NOT_HANDLED; 
                break;
            }

            case EXIT_PROCESS_DEBUG_EVENT: {
                child_exit_code = debug_event.u.ExitProcess.dwExitCode;
                printf("[+] Child exited with code: %lu\n", child_exit_code);
                cont = DBG_CONTINUE;
                done = TRUE;
                break;
            }
        }
        ContinueDebugEvent(debug_event.dwProcessId, debug_event.dwThreadId, cont);
    }

    if (g_hProc) {
        WaitForSingleObject(g_hProc, 0);
        CloseHandle(g_hProc);
    }
    if (pi.hThread) CloseHandle(pi.hThread);

    free(cmdline);
    free(g_dll_block_list);
    return (int)child_exit_code;
}
