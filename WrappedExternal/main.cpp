#define PSAPI_VERSION 1
#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>
#include <Psapi.h>

/*
    FindProcessId and GetProcessBaseAddress functions were found on stackoverflow
*/
unsigned long long GetProcessBaseAddress(DWORD processID)
{
     
    unsigned long long   baseAddress = 0;
    HANDLE      processHandle = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processID);
    HMODULE* moduleArray;
    LPBYTE      moduleArrayBytes;
    DWORD       bytesRequired;

    if (processHandle)
    {
        if (EnumProcessModules(processHandle, NULL, 0, &bytesRequired))
        {
            if (bytesRequired)
            {
                moduleArrayBytes = (LPBYTE)LocalAlloc(LPTR, bytesRequired);

                if (moduleArrayBytes)
                {
                    unsigned int moduleCount;

                    moduleCount = bytesRequired / sizeof(HMODULE);
                    moduleArray = (HMODULE*)moduleArrayBytes;

                    if (EnumProcessModules(processHandle, moduleArray, bytesRequired, &bytesRequired))
                    {
                        baseAddress = (unsigned long long)moduleArray[0];
                    }

                    LocalFree(moduleArrayBytes);
                }
            }
        }

        CloseHandle(processHandle);
    }

    return baseAddress;
}
DWORD FindProcessId(const std::wstring& processName)
{
    PROCESSENTRY32 processInfo;
    processInfo.dwSize = sizeof(processInfo);

    HANDLE processesSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
    if (processesSnapshot == INVALID_HANDLE_VALUE) {
        return 0;
    }

    Process32First(processesSnapshot, &processInfo);
    if (!processName.compare(processInfo.szExeFile))
    {
        CloseHandle(processesSnapshot);
        return processInfo.th32ProcessID;
    }

    while (Process32Next(processesSnapshot, &processInfo))
    {
        if (!processName.compare(processInfo.szExeFile))
        {
            CloseHandle(processesSnapshot);
            return processInfo.th32ProcessID;
        }
    }

    CloseHandle(processesSnapshot);
    return 0;
}
void unlock_all_ext()
{
    unsigned char UnlockAllShellcode[89] =
    {
     0x53, 0x48, 0x83, 0xEC, 0x20, 0x48, 0xB8, 0x00,
     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xFF,
     0xD0, 0x48, 0x8D, 0x54, 0x24, 0x28, 0x48, 0x89,
     0xC3, 0x48, 0x8B, 0x42, 0x30, 0x48, 0x89, 0xC1,
     0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
     0x00, 0x00, 0x48, 0x29, 0xC1, 0x48, 0x81, 0xF9,
     0xD1, 0x0A, 0xA2, 0x01, 0x75, 0x1A, 0x48, 0x8B,
     0x42, 0x30, 0x48, 0x8D, 0x48, 0x68, 0x48, 0x89,
     0x4A, 0x30, 0x48, 0x89, 0xF8, 0xC6, 0x40, 0x52,
     0x00, 0x48, 0x89, 0xF8, 0xC6, 0x40, 0x51, 0x00,
     0x48, 0x89, 0xD8, 0x48, 0x83, 0xC4, 0x20, 0x5B,
     0xC3
    };

    DWORD Pid = FindProcessId(L"RainbowSix.exe");
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, Pid);
    unsigned long long GameBaseAddress = GetProcessBaseAddress(Pid);
    unsigned long long Buffer = NULL;

    LPVOID AllocatedMemory = VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    ReadProcessMemory(hProcess, (LPCVOID)(GameBaseAddress + 0x5AE06F0), &Buffer, sizeof(unsigned long long), NULL);
    *(unsigned long long*)(&UnlockAllShellcode[0x7]) = Buffer;
    *(unsigned long long*)(&UnlockAllShellcode[0x22]) = (unsigned long long)GameBaseAddress;

    WriteProcessMemory(hProcess, AllocatedMemory, UnlockAllShellcode, sizeof(UnlockAllShellcode), NULL);
    WriteProcessMemory(hProcess, (LPVOID)(GameBaseAddress + 0x5AE06F0), &AllocatedMemory, sizeof(unsigned __int64), NULL);
}
int main()
{
    unlock_all_ext();
    return 0;
}
