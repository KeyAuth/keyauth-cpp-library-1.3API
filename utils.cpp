#include "utils.hpp"

#include <vector>
#include "Syscaller/syscall.hpp"


std::string utils::get_hwid() {
    /**
     * @brief Get current users SID via direct syscalls
     * @details
     * we wanna do this so we can prevent hooking of atlSecurity.h functions which calls advapi32.dll functions
     *
     * @warning still fuckable if they hook the function, owner needs to obfuscate 
     */

    static SyscallSectionDirect syscallManager;
    static bool initialized = false;

    if (!initialized) {
        if (!syscallManager.initialize()) {
            // shouldnt happen, tested on various systems
            return "none";
        }
        initialized = true;
    }

    HANDLE hToken = nullptr;
    ULONG returnLength = 0;

    NTSTATUS status = syscallManager.invoke<NTSTATUS>(
        SYSCALL_ID("NtOpenProcessToken"),
        GetCurrentProcess(),
        TOKEN_QUERY,
        &hToken
    );

    if (!NT_SUCCESS(status))
        return "none";

    syscallManager.invoke<NTSTATUS>(SYSCALL_ID("NtQueryInformationToken"), hToken, TokenUser, nullptr, 0, &returnLength);
    std::vector<BYTE> buffer(returnLength);

    status = syscallManager.invoke<NTSTATUS>(SYSCALL_ID("NtQueryInformationToken"), hToken, TokenUser, buffer.data(), returnLength, &returnLength);
    CloseHandle(hToken);

    if (!NT_SUCCESS(status))
        return "none";

    PTOKEN_USER pTokenUser = (PTOKEN_USER)buffer.data();
    PSID pSid = pTokenUser->User.Sid;

    if (!pSid)
        return "none";

    // normally we would go with ConvertSidToStringSidW 
    // but since the return data can be faked we need to do it manually
    BYTE* sid = (BYTE*)pSid;
    DWORD subAuthCount = sid[1];

    std::string result = XorStr("S-1-");

    DWORD authority = 0;
    for (int i = 2; i < 8; i++)
        authority = (authority << 8) | sid[i];

    result += std::to_string(authority);

    DWORD* subAuth = (DWORD*)(sid + 8);
    for (DWORD i = 0; i < subAuthCount; i++) {
        result += "-";
        result += std::to_string(subAuth[i]);
    }

    return result;
}

std::time_t utils::string_to_timet(std::string timestamp) {
	auto cv = strtol(timestamp.c_str(), NULL, 10);

	return (time_t)cv;
}

std::tm utils::timet_to_tm(time_t timestamp) {
	std::tm context;

	localtime_s(&context, &timestamp);

	return context;
}
