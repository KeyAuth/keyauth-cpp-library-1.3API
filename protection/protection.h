#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <chrono>
#include <array>

#include "../Protection/Hooking/Detours/detours.h"
#include "../protection/hooking/hooking/hooking.h"
#include "../protection/antiDLL/antiDLL.h"
#include "xorstr.hpp"

class CProtection {
public:
    // Used to hook own functions if not external
    template <typename T, typename M>
    static void* MemberToFuncPtr(M T::* member) {
        return *reinterpret_cast<void**>(&member);
    }
    static bool InitializeProtection();
    static void VerifySecurityStatus();
    static DWORD WINAPI cerberus(LPVOID lpParam);

    inline static DWORD g_sentinelTid = 0;
    inline static std::atomic<ULONGLONG> g_cerberusHeartbeat{ 0 };
private:
    inline static std::once_flag x64_trap_flag;
    inline static void* x64_trap_asm = nullptr;

    static bool CheckHardwareBreakpoints();
    static bool MethodTrapFlag();
};
