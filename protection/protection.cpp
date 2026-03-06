#pragma once
#include "protection.h"
#include <thread>
#include "utils.hpp"

/** Protection
 * @brief Implements the client Security
 * @details
 * Hooks winAPI functions and places Security functions in them
 * will add integrity checks later.
 * 
 * @warning user has to protect important functions. [ cerberus(), InitializeProtection() & VerifySecurityStatus() ]
 * @author https://github.com/officialchristheg
*/

inline bool CProtection::CheckHardwareBreakpoints()
{
    CONTEXT ctx;
    memset(&ctx, 0, sizeof(CONTEXT));

    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (GetThreadContext(GetCurrentThread(), &ctx) == 0)
        return false;

    if (ctx.Dr0 != 0 || ctx.Dr1 != 0 || ctx.Dr2 != 0 || ctx.Dr3 != 0)
        return true;

    return false;
}

inline bool CProtection::MethodTrapFlag()
{
    __try
    {
        std::call_once(x64_trap_flag, [] {
            byte function_asm[] =
            {
                0x9c,                               // pushf
                0x66, 0x81, 0x0C, 0x24, 0x00, 0x01, // or WORD PTR[rsp], 0x100
                0x9d,                               // popf
                0x90,                               // nop
                0xC3,                               // ret
            };

            x64_trap_asm = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            memcpy(x64_trap_asm, function_asm, sizeof(function_asm));

            DWORD old;
            VirtualProtect(x64_trap_asm, 0x1000, PAGE_EXECUTE_READ, &old);
            });

        reinterpret_cast<void(*)()>(x64_trap_asm)();
    }
    __except (1)
    {
        return false;
    }
    return true;
}

DWORD WINAPI CProtection::cerberus(LPVOID) {
    for (;;) {
        g_cerberusHeartbeat.store(GetTickCount64(), std::memory_order_relaxed);
        std::this_thread::sleep_for(std::chrono::milliseconds(500));

        AntiDLL::Detection();

        if (CheckHardwareBreakpoints()) {
            utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0008000").c_str());
        }

        if (MethodTrapFlag()) {
            utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0008000").c_str());
        }
    }
}

void CProtection::VerifySecurityStatus() {
    if (!g_sentinelTid)
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0008000").c_str());

    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_SUSPEND_RESUME | SYNCHRONIZE, FALSE, g_sentinelTid);
    if (!hThread)
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0008000").c_str());

    DWORD exitCode = 0;
    if (!GetExitCodeThread(hThread, &exitCode) || exitCode != STILL_ACTIVE) {
        CloseHandle(hThread);
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0008000").c_str());
    }

    DWORD suspendCount = ResumeThread(hThread);
    if (suspendCount != (DWORD)-1) {
        if (suspendCount > 0) {
            SuspendThread(hThread);
            CloseHandle(hThread);
            utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0008000").c_str());
        }
    }

    CloseHandle(hThread);
}

bool CProtection::InitializeProtection() {
    if (DetourTransactionBegin() != NO_ERROR)
        return false;

    HMODULE hNtdll = GetModuleHandleW(XorStr(L"ntdll.dll").c_str());

    DetourUpdateThread(GetCurrentThread());
    DetourAttach(&(PVOID&)hooks::TrueDebugActiveProcess, hooks::HookedDebugActiveProcess);
    DetourAttach(&(PVOID&)hooks::TrueVirtualAllocEx, hooks::HookedVirtualAllocEx);
    DetourAttach(&(PVOID&)hooks::TrueReadProcessMemory, hooks::HookedReadProcessMemory);
    DetourAttach(&(PVOID&)hooks::TrueWriteProcessMemory, hooks::HookedWriteProcessMemory);
    DetourAttach(&(PVOID&)hooks::TrueCreateRemoteThread, hooks::HookedCreateRemoteThread);
    DetourAttach(&(PVOID&)hooks::TrueCreateRemoteThreadEx, hooks::HookedCreateRemoteThreadEx);
    DetourAttach(&(PVOID&)hooks::TrueQueueUserAPC, hooks::HookedQueueUserAPC);
    DetourAttach(&(PVOID&)hooks::TrueOpenProcess, hooks::HookedOpenProcess);
    DetourAttach(&(PVOID&)hooks::TrueCreateFileA, hooks::HookedCreateFileA);
    DetourAttach(&(PVOID&)hooks::TrueCreateFileW, hooks::HookedCreateFileW);
    DetourAttach(&(PVOID&)hooks::TrueDeleteFileA, hooks::HookedDeleteFileA);
    DetourAttach(&(PVOID&)hooks::TrueDeleteFileW, hooks::HookedDeleteFileW);
    DetourAttach(&(PVOID&)hooks::TrueCreateProcessA, hooks::HookedCreateProcessA);
    DetourAttach(&(PVOID&)hooks::TrueCreateProcessW, hooks::HookedCreateProcessW);
    DetourAttach(&(PVOID&)hooks::TrueNtSuspendThread, hooks::HookedNtSuspendThread);
    DetourAttach(&(PVOID&)hooks::TrueZwSuspendThread, hooks::HookedZwSuspendThread);
    DetourAttach(&(PVOID&)hooks::TrueNtReadVirtualMemory, hooks::HookedNtReadVirtualMemory);
    DetourAttach(&(PVOID&)hooks::TrueNtWriteVirtualMemory, hooks::HookedNtWriteVirtualMemory);

    if (DetourTransactionCommit() != NO_ERROR)
        return false;

    auto ntRead = (void*)GetProcAddress(hNtdll, "NtReadVirtualMemory");
    auto ntWrite = (void*)GetProcAddress(hNtdll, "NtWriteVirtualMemory");
    auto ntSuspend = (void*)GetProcAddress(hNtdll, "NtSuspendThread");
    auto zwSuspend = (void*)GetProcAddress(hNtdll, "ZwSuspendThread");

    HANDLE hSentinel = CreateThread(NULL, 0, CProtection::cerberus, NULL, 0, &g_sentinelTid);
    if (!hSentinel) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0008000").c_str());
        return false;
    }

    return true;
}
