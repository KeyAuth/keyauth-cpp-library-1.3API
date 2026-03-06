#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include "xorstr.hpp"
#include <TlHelp32.h>

namespace utils
{
	std::string get_hwid();
	std::time_t string_to_timet(std::string timestamp);
	std::tm timet_to_tm(time_t timestamp);

    inline void raiseTermination(const char* code)
    {
        std::string msg = std::string(XorStr("An unexpected condition was encountered.\nError code: ")) + code;
        MessageBoxA(nullptr, msg.c_str(), "KeyAuth", MB_TOPMOST | MB_SETFOREGROUND | MB_ICONERROR);
        __fastfail(0);
    }

    inline DWORD OwnerPidFromTid(DWORD tid)
    {
        DWORD owner = 0;
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te{ sizeof(te) };
            if (Thread32First(snap, &te)) {
                do {
                    if (te.th32ThreadID == tid) {
                        owner = te.th32OwnerProcessID;
                        break;
                    }
                } while (Thread32Next(snap, &te));
            }
            CloseHandle(snap);
        }
        return owner;
    }
}