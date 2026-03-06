#pragma once
#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <chrono>

namespace hooks {
    typedef BOOL(WINAPI* DebugActiveProcess_t)(DWORD);
    typedef LPVOID(WINAPI* VirtualAllocEx_t)(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    typedef BOOL(WINAPI* ReadProcessMemory_t)(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    typedef BOOL(WINAPI* WriteProcessMemory_t)(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    typedef HANDLE(WINAPI* CreateRemoteThread_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    typedef HANDLE(WINAPI* CreateRemoteThreadEx_t)(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
    typedef DWORD(WINAPI* QueueUserAPC_t)(PAPCFUNC, HANDLE, ULONG_PTR);
    typedef HANDLE(WINAPI* OpenProcess_t)(DWORD, BOOL, DWORD);
    typedef HANDLE(WINAPI* CreateFileA_t)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef HANDLE(WINAPI* CreateFileW_t)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    typedef BOOL(WINAPI* DeleteFileA_t)(LPCSTR);
    typedef BOOL(WINAPI* DeleteFileW_t)(LPCWSTR);
    typedef BOOL(WINAPI* CreateProcessA_t)(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    typedef BOOL(WINAPI* CreateProcessW_t)(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    typedef NTSTATUS(NTAPI* NtSuspendThread_t)(HANDLE, PULONG);
    typedef NTSTATUS(NTAPI* ZwSuspendThread_t)(HANDLE, PULONG);
    typedef NTSTATUS(NTAPI* NtReadVirtualMemory_t)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
    typedef NTSTATUS(NTAPI* NtWriteVirtualMemory_t)(HANDLE, PVOID, CONST VOID*, SIZE_T, PSIZE_T);

    BOOL WINAPI HookedDebugActiveProcess(DWORD dwProcessId);
    HANDLE WINAPI HookedCreateFileA(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    HANDLE WINAPI HookedCreateFileW(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
    BOOL WINAPI HookedDeleteFileA(LPCSTR);
    BOOL WINAPI HookedDeleteFileW(LPCWSTR);
    BOOL WINAPI HookedCreateProcessA(LPCSTR, LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCSTR, LPSTARTUPINFOA, LPPROCESS_INFORMATION);
    BOOL WINAPI HookedCreateProcessW(LPCWSTR, LPWSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, BOOL, DWORD, LPVOID, LPCWSTR, LPSTARTUPINFOW, LPPROCESS_INFORMATION);
    BOOL WINAPI HookedReadProcessMemory(HANDLE, LPCVOID, LPVOID, SIZE_T, SIZE_T*);
    BOOL WINAPI HookedWriteProcessMemory(HANDLE, LPVOID, LPCVOID, SIZE_T, SIZE_T*);
    LPVOID WINAPI HookedVirtualAllocEx(HANDLE, LPVOID, SIZE_T, DWORD, DWORD);
    HANDLE WINAPI HookedCreateRemoteThread(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPDWORD);
    HANDLE WINAPI HookedCreateRemoteThreadEx(HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, LPVOID, DWORD, LPPROC_THREAD_ATTRIBUTE_LIST, LPDWORD);
    DWORD  WINAPI HookedQueueUserAPC(PAPCFUNC, HANDLE, ULONG_PTR);
    HANDLE WINAPI HookedOpenProcess(DWORD, BOOL, DWORD);
    BOOL WINAPI HookedGetThreadContext(HANDLE, LPCONTEXT);
    BOOL WINAPI HookedSetThreadContext(HANDLE, CONST CONTEXT*);
    NTSTATUS NTAPI HookedNtSuspendThread(HANDLE hThread, PULONG PreviousSuspendCount);
    NTSTATUS NTAPI HookedZwSuspendThread(HANDLE hThread, PULONG PreviousSuspendCount);
    NTSTATUS NTAPI HookedNtReadVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, PVOID Buffer, SIZE_T Size, PSIZE_T NumberOfBytesRead);
    NTSTATUS NTAPI HookedNtWriteVirtualMemory(HANDLE ProcessHandle, PVOID BaseAddress, CONST VOID* Buffer, SIZE_T Size, PSIZE_T NumberOfBytesWritten);

    inline DebugActiveProcess_t TrueDebugActiveProcess = (DebugActiveProcess_t)::DebugActiveProcess;
    inline VirtualAllocEx_t TrueVirtualAllocEx = ::VirtualAllocEx;
    inline ReadProcessMemory_t TrueReadProcessMemory = ::ReadProcessMemory;
    inline WriteProcessMemory_t TrueWriteProcessMemory = ::WriteProcessMemory;
    inline CreateRemoteThread_t TrueCreateRemoteThread = ::CreateRemoteThread;
    inline CreateRemoteThreadEx_t TrueCreateRemoteThreadEx = ::CreateRemoteThreadEx;
    inline QueueUserAPC_t TrueQueueUserAPC = ::QueueUserAPC;
    inline OpenProcess_t TrueOpenProcess = ::OpenProcess;
    inline CreateFileA_t TrueCreateFileA = ::CreateFileA;
    inline CreateFileW_t TrueCreateFileW = ::CreateFileW;
    inline DeleteFileA_t TrueDeleteFileA = ::DeleteFileA;
    inline DeleteFileW_t TrueDeleteFileW = ::DeleteFileW;
    inline CreateProcessA_t TrueCreateProcessA = ::CreateProcessA;
    inline CreateProcessW_t TrueCreateProcessW = ::CreateProcessW;
    inline NtSuspendThread_t TrueNtSuspendThread = (NtSuspendThread_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtSuspendThread");
    inline ZwSuspendThread_t TrueZwSuspendThread = (ZwSuspendThread_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "ZwSuspendThread");
    inline NtReadVirtualMemory_t TrueNtReadVirtualMemory = (NtReadVirtualMemory_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtReadVirtualMemory");
    inline NtWriteVirtualMemory_t TrueNtWriteVirtualMemory = (NtWriteVirtualMemory_t)GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtWriteVirtualMemory");
}
