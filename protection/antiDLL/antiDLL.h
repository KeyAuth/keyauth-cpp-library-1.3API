#pragma once
#include <Windows.h>
#include <TlHelp32.h>
#include <cwchar>

class AntiDLL {
public:
    static void SetValid(bool valid) { IsValid = valid; }

    static void Detection();

private:
    static bool IsDllLoaded(const wchar_t* dllName);
    static void DetectX64dbg();
    static void DetectCheatEngine();
    static void DetectEchoMirage();

    inline static bool IsValid = true;
};
