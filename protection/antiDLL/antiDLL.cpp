#include "antiDLL.h"
#include "xorstr.hpp"
#include "utils.hpp"

bool AntiDLL::IsDllLoaded(const wchar_t* dllName) {
    if (GetModuleHandleW(dllName) != nullptr) {
        return true;
    }

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) {
        return false;
    }

    PROCESSENTRY32W pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32W);

    if (!Process32FirstW(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        return false;
    }

    bool found = false;
    do {
        if (pe32.th32ProcessID <= 4)
            continue;

        HANDLE hModuleSnapshot = CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32,
            pe32.th32ProcessID
        );

        if (hModuleSnapshot == INVALID_HANDLE_VALUE) {
            continue;
        }

        MODULEENTRY32W me32;
        me32.dwSize = sizeof(MODULEENTRY32W);

        if (Module32FirstW(hModuleSnapshot, &me32)) {
            do {
                if (_wcsicmp(me32.szModule, dllName) == 0) {
                    found = true;
                    CloseHandle(hModuleSnapshot);
                    goto cleanup; 
                }
            } while (Module32NextW(hModuleSnapshot, &me32));
        }

        CloseHandle(hModuleSnapshot);

    } while (Process32NextW(hSnapshot, &pe32));

cleanup:
    CloseHandle(hSnapshot);
    return found;
}

void AntiDLL::DetectX64dbg() {
    if (IsValid) {
        const wchar_t* dllName = (XorStr(L"x64dbg.dll").c_str());
        if (IsDllLoaded(dllName)) {
            utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000605").c_str());
        }
    }
}

void AntiDLL::DetectCheatEngine() {
    if (IsValid) {
        const wchar_t* dllName = (XorStr(L"lua53-64.dll").c_str());
        if (IsDllLoaded(dllName)) {
            utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000904").c_str());
        }
    }
}

void AntiDLL::DetectEchoMirage() {
    if (IsValid) {
        const wchar_t* dllName = (XorStr(L"EchoMirageHooks64.dll").c_str());
        if (IsDllLoaded(dllName)) {
            utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000902").c_str());
        }
    }
}

void AntiDLL::Detection() {
    AntiDLL::DetectCheatEngine();
    AntiDLL::DetectEchoMirage();
    AntiDLL::DetectX64dbg();
}