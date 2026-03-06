#include "hooking.h"
#include "utils.hpp"
#include "xorstr.hpp"
#include "../protection/protection.h"

HANDLE WINAPI hooks::HookedCreateFileA(LPCSTR lpFileName, DWORD access, DWORD share,
    LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE hTemplate)
{
    DWORD callerPid = GetCurrentProcessId();
    if (GetProcessIdOfThread(GetCurrentThread()) != callerPid) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000034").c_str());
    }
    return TrueCreateFileA(lpFileName, access, share, sa, disp, flags, hTemplate);
}

HANDLE WINAPI hooks::HookedCreateFileW(LPCWSTR lpFileName, DWORD access, DWORD share,
    LPSECURITY_ATTRIBUTES sa, DWORD disp, DWORD flags, HANDLE hTemplate)
{
    DWORD callerPid = GetCurrentProcessId();
    if (GetProcessIdOfThread(GetCurrentThread()) != callerPid) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000034").c_str());
    }
    return TrueCreateFileW(lpFileName, access, share, sa, disp, flags, hTemplate);
}

BOOL WINAPI hooks::HookedDeleteFileA(LPCSTR lpFileName) {
    if (GetProcessIdOfThread(GetCurrentThread()) != GetCurrentProcessId()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000022").c_str());
    }
    return TrueDeleteFileA(lpFileName);
}

BOOL WINAPI hooks::HookedDeleteFileW(LPCWSTR lpFileName) {
    if (GetProcessIdOfThread(GetCurrentThread()) != GetCurrentProcessId()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000022").c_str());
    }
    return TrueDeleteFileW(lpFileName);
}

BOOL WINAPI hooks::HookedCreateProcessA(LPCSTR app, LPSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env,
    LPCSTR dir, LPSTARTUPINFOA si, LPPROCESS_INFORMATION pi)
{
    if (GetProcessIdOfThread(GetCurrentThread()) != GetCurrentProcessId()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000184").c_str());
    }
    return TrueCreateProcessA(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}

BOOL WINAPI hooks::HookedCreateProcessW(LPCWSTR app, LPWSTR cmd, LPSECURITY_ATTRIBUTES pa,
    LPSECURITY_ATTRIBUTES ta, BOOL inherit, DWORD flags, LPVOID env,
    LPCWSTR dir, LPSTARTUPINFOW si, LPPROCESS_INFORMATION pi)
{
    if (GetProcessIdOfThread(GetCurrentThread()) != GetCurrentProcessId()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000181").c_str());
    }
    return TrueCreateProcessW(app, cmd, pa, ta, inherit, flags, env, dir, si, pi);
}

BOOL WINAPI hooks::HookedReadProcessMemory(HANDLE hProcess, LPCVOID base, LPVOID buf, SIZE_T n, SIZE_T* out) {
    DWORD pid = GetProcessId(hProcess);
    if (pid == GetCurrentProcessId() && hProcess != GetCurrentProcess()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000005").c_str());
    }
    return TrueReadProcessMemory(hProcess, base, buf, n, out);
}

BOOL WINAPI hooks::HookedWriteProcessMemory(HANDLE hProcess, LPVOID base, LPCVOID buf, SIZE_T n, SIZE_T* out) {
    DWORD pid = GetProcessId(hProcess);
    if (pid == GetCurrentProcessId() && hProcess != GetCurrentProcess()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000022").c_str());
    }
    return TrueWriteProcessMemory(hProcess, base, buf, n, out);
}

LPVOID WINAPI hooks::HookedVirtualAllocEx(HANDLE hProcess, LPVOID addr, SIZE_T sz, DWORD type, DWORD prot) {
    DWORD pid = GetProcessId(hProcess);
    if ((prot & (PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_READ))) {
        if ((pid == GetCurrentProcessId() && hProcess != GetCurrentProcess()) || (pid != GetCurrentProcessId())) {
            utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xE001FA9B").c_str());
        }
    }
    return TrueVirtualAllocEx(hProcess, addr, sz, type, prot);
}

BOOL WINAPI hooks::HookedDebugActiveProcess(DWORD dwProcessId) {
    utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xE001FA9A").c_str());


    return TrueDebugActiveProcess(dwProcessId);
}

HANDLE WINAPI hooks::HookedCreateRemoteThread(HANDLE hProcess, LPSECURITY_ATTRIBUTES sa, SIZE_T st,
    LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags, LPDWORD tid) {
    DWORD pid = GetProcessId(hProcess);
    if (pid == GetCurrentProcessId() && hProcess != GetCurrentProcess()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000142").c_str());
    }
    return TrueCreateRemoteThread(hProcess, sa, st, start, param, flags, tid);
}

HANDLE WINAPI hooks::HookedCreateRemoteThreadEx(HANDLE hProcess, LPSECURITY_ATTRIBUTES sa, SIZE_T st,
    LPTHREAD_START_ROUTINE start, LPVOID param, DWORD flags,
    LPPROC_THREAD_ATTRIBUTE_LIST attrs, LPDWORD tid) {
    DWORD pid = GetProcessId(hProcess);
    if (pid == GetCurrentProcessId() && hProcess != GetCurrentProcess()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0x80004005").c_str());
    }
    return TrueCreateRemoteThreadEx(hProcess, sa, st, start, param, flags, attrs, tid);
}

DWORD WINAPI hooks::HookedQueueUserAPC(PAPCFUNC pfnAPC, HANDLE hThread, ULONG_PTR data) {
    DWORD tid = GetThreadId(hThread);
    if (utils::OwnerPidFromTid(tid) == GetCurrentProcessId()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0x00003FF").c_str());
    }
    return TrueQueueUserAPC(pfnAPC, hThread, data);
}

HANDLE WINAPI hooks::HookedOpenProcess(DWORD access, BOOL inherit, DWORD pid) {
    if (pid == GetCurrentProcessId() && (access & (PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION | PROCESS_ALL_ACCESS))) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000095").c_str());
    }
    return TrueOpenProcess(access, inherit, pid);
}

NTSTATUS NTAPI hooks::HookedNtSuspendThread(HANDLE hThread, PULONG PreviousSuspendCount) {
    DWORD tid = GetThreadId(hThread);
    if (tid == CProtection::g_sentinelTid) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000112").c_str());
    }

    return TrueNtSuspendThread(hThread, PreviousSuspendCount);
}

NTSTATUS NTAPI hooks::HookedZwSuspendThread(HANDLE hThread, PULONG PreviousSuspendCount) {
    DWORD tid = GetThreadId(hThread);
    if (tid == CProtection::g_sentinelTid) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000114").c_str());
    }

    return TrueZwSuspendThread(hThread, PreviousSuspendCount);
}

NTSTATUS NTAPI hooks::HookedNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T Size, PSIZE_T NumberOfBytesRead) {
    DWORD pid = GetProcessId(ProcessHandle);
    if (pid == GetCurrentProcessId() && ProcessHandle != GetCurrentProcess()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000005").c_str());
    }
    return TrueNtReadVirtualMemory(ProcessHandle, BaseAddress, Buffer, Size, NumberOfBytesRead);
}

NTSTATUS NTAPI hooks::HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, CONST VOID* Buffer, SIZE_T Size, PSIZE_T NumberOfBytesWritten) {
    DWORD pid = GetProcessId(ProcessHandle);
    if (pid == GetCurrentProcessId() && ProcessHandle != GetCurrentProcess()) {
        utils::raiseTermination(XorStr("KeyAuth Security Violation: 0xC0000022").c_str());
    }
    return TrueNtWriteVirtualMemory(ProcessHandle, BaseAddress, Buffer, Size, NumberOfBytesWritten);
}
