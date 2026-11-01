#ifndef UNICODE
#define UNICODE
#endif

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0600
#endif

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#define _CRT_SECURE_NO_WARNINGS

#define KA_EXIT(code) throw KeyAuth::request_error("KeyAuth operation rejected (code " + std::to_string(code) + ").")

#include <auth.hpp>
#include <dpapi.h>
#include <lmcons.h>
#pragma comment(lib, "crypt32.lib")
#include <strsafe.h> 
#include <windows.h>
#include <string>
#include <stdio.h>
#include <iostream>

#include <shellapi.h>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")

#include <sstream> 
#include <iomanip> 
#include <xorstr.hpp>
#include <fstream> 
#include <http.h>
#include <stdlib.h>
#include <windns.h>

#include <ctime>
#include <filesystem>

#pragma comment(lib, "rpcrt4.lib")
#pragma comment(lib, "httpapi.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "wintrust.lib")
#pragma comment(lib, "dnsapi.lib")
#pragma comment(lib, "secur32.lib")
#pragma comment(lib, "iphlpapi.lib")

#include <cstdio>
#include <iostream>
#include <memory>
#include <algorithm>
#include <psapi.h>
#include <wintrust.h>
#include <softpub.h>
#include <cwctype>
#include <intrin.h>
#include <array>
#include <cstring>
#include <vector>
#include <utility>
#include <stdexcept>
#include <ws2tcpip.h>
#include <windns.h>
#include <tlhelp32.h>
#include <string>
#include <array>

#include <functional>
#include <vector>
#include <bitset>
#include <psapi.h>
#pragma comment( lib, "psapi.lib" )
#include <thread>

#include <cctype>
#include <algorithm>

#if __has_include("Security.hpp")
#include "Security.hpp"
#define KEYAUTH_HAVE_SECURITY 1
#else
#define KEYAUTH_HAVE_SECURITY 0
#endif

#if __has_include("killEmulator.hpp")
#include "killEmulator.hpp"
#define KEYAUTH_HAVE_KILLEMU 1
#else
#define KEYAUTH_HAVE_KILLEMU 0
#endif
#include <lazy_importer.hpp>
#include <QRCode/qrcode.hpp>
#include <QRCode/qr.png.h>

#define SHA256_HASH_SIZE 32

std::string get_str_between_two_str(const std::string& s, const std::string& start_delim, const std::string& stop_delim);
int VerifyPayload(const std::string& signature, const std::string& timestamp, const std::string& body, long long received_at = 0);

std::string checksum();
[[noreturn]] void error(std::string message);
std::string generate_random_number();
std::string curl_escape(CURL* curl, const std::string& input);
void integrity_check();
std::string extract_host(const std::string& url);
bool hosts_override_present(const std::string& host);
bool module_has_rwx_section(HMODULE mod);
bool core_modules_signed();
static std::wstring get_system_dir();
static std::wstring get_syswow_dir();

bool timing_anomaly_detected();


void snapshot_text_hashes();
bool text_hashes_ok();
void snapshot_text_page_protections();
bool text_page_protections_ok();
void snapshot_data_page_protections();
bool data_page_protections_ok();
static bool get_text_section_info(std::uintptr_t& base, size_t& size);
static uint32_t rolling_crc32(const uint8_t* data, size_t len, size_t window = 64, size_t stride = 16);
 
inline void secure_zero(std::string& value) noexcept;
inline void securewipe(std::string& value) noexcept;
std::string seed;
void cleanUpSeedData(const std::string& seed);
thread_local std::string signature;
thread_local std::string signatureTimestamp;


using SignatureHeaders = keyauth_detail::SignatureHeaders;

static inline void trim_ws(std::string& s) {
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.erase(s.begin());
    while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.pop_back();
}

static inline void strip_quotes(std::string& s) {
    if (s.size() >= 2 && ((s.front() == '"' && s.back() == '"') || (s.front() == '\'' && s.back() == '\''))) {
        s = s.substr(1, s.size() - 2);
    }
}

static inline bool is_hex_string(const std::string& s) {
    return !s.empty() && std::all_of(s.begin(), s.end(), [](unsigned char c) { return std::isxdigit(c) != 0; });
}

static inline std::string bytes_to_hex(const unsigned char* bytes, size_t len) {
    static const char* kHex = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (size_t i = 0; i < len; ++i) {
        out.push_back(kHex[(bytes[i] >> 4) & 0xF]);
        out.push_back(kHex[bytes[i] & 0xF]);
    }
    return out;
}

static bool normalize_signature_header(std::string sig_in, std::string& sig_hex_out) {
    trim_ws(sig_in);
    strip_quotes(sig_in);
    if (sig_in.rfind("0x", 0) == 0 || sig_in.rfind("0X", 0) == 0) {
        sig_in = sig_in.substr(2);
    }

    if (is_hex_string(sig_in) && sig_in.size() == 128) {
        std::transform(sig_in.begin(), sig_in.end(), sig_in.begin(),
            [](unsigned char c) { return keyauth_detail::ascii_lower(c); });
        sig_hex_out = sig_in;
        return true;
    }

    unsigned char decoded[64] = { 0 };
    size_t decoded_len = 0;
    if (sodium_base642bin(decoded, sizeof(decoded), sig_in.c_str(), sig_in.size(),
            nullptr, &decoded_len, nullptr, sodium_base64_VARIANT_ORIGINAL) == 0 && decoded_len == 64) {
        sig_hex_out = bytes_to_hex(decoded, decoded_len);
        return true;
    }
    if (sodium_base642bin(decoded, sizeof(decoded), sig_in.c_str(), sig_in.size(),
            nullptr, &decoded_len, nullptr, sodium_base64_VARIANT_URLSAFE_NO_PADDING) == 0 && decoded_len == 64) {
        sig_hex_out = bytes_to_hex(decoded, decoded_len);
        return true;
    }
    return false;
}

static constexpr uint8_t k_pubkey_xor1 = 0x5A;
static constexpr uint8_t k_pubkey_xor2 = 0xA5;
static constexpr uint64_t k_pubkey_fnv1a = 0x7553f24ca052d4b1ULL;
static const uint8_t k_pubkey_obf1[64] = {
    0x6f, 0x6f, 0x62, 0x6c, 0x38, 0x6e, 0x38, 0x39, 0x6c, 0x63, 0x39, 0x6d, 0x3b, 0x6e, 0x38, 0x6e,
    0x62, 0x6d, 0x3f, 0x6e, 0x6f, 0x6c, 0x69, 0x3b, 0x6e, 0x39, 0x3e, 0x63, 0x6c, 0x3b, 0x3c, 0x3e,
    0x69, 0x63, 0x6b, 0x6e, 0x6a, 0x3c, 0x63, 0x6b, 0x63, 0x38, 0x3e, 0x69, 0x6b, 0x39, 0x3f, 0x3b,
    0x6d, 0x3e, 0x6b, 0x39, 0x6c, 0x3b, 0x6b, 0x3f, 0x62, 0x6e, 0x69, 0x63, 0x6e, 0x68, 0x68, 0x38
};
static const uint8_t k_pubkey_obf2[64] = {
    0x90, 0x90, 0x9d, 0x93, 0xc7, 0x91, 0xc7, 0xc6, 0x93, 0x9c, 0xc6, 0x92, 0xc4, 0x91, 0xc7, 0x91,
    0x9d, 0x92, 0xc0, 0x91, 0x90, 0x93, 0x96, 0xc4, 0x91, 0xc6, 0xc1, 0x9c, 0x93, 0xc4, 0xc3, 0xc1,
    0x96, 0x9c, 0x94, 0x91, 0x95, 0xc3, 0x9c, 0x94, 0x9c, 0xc7, 0xc1, 0x96, 0x94, 0xc6, 0xc0, 0xc4,
    0x92, 0xc1, 0x94, 0xc6, 0x93, 0xc4, 0x94, 0xc0, 0x9d, 0x91, 0x96, 0x9c, 0x91, 0x97, 0x97, 0xc7
};
static std::atomic<uint64_t> pubkey_hash_seen{ 0 };
static std::atomic<bool> pubkey_protect_ready{ false };
static DWORD pubkey_protect_baseline = 0;
bool KeyAuth::api::debug = false;

std::atomic<long long> last_integrity_check{ 0 };
std::atomic<int> integrity_fail_streak{ 0 };
std::atomic<long long> last_module_check{ 0 };
std::atomic<long long> last_periodic_check{ 0 };
std::atomic<bool> text_hashes_ready{ false };
struct TextHash { size_t offset; size_t len; uint32_t hash; };
std::vector<TextHash> text_hashes;
std::atomic<bool> text_prot_ready{ false };
std::vector<std::pair<std::uintptr_t, DWORD>> text_protections;
std::atomic<bool> data_prot_ready{ false };
std::vector<std::pair<std::uintptr_t, DWORD>> data_protections;
std::atomic<int> heavy_fail_streak{ 0 };
static std::atomic<uint32_t> text_crc_baseline{ 0 };
static std::atomic<uint32_t> curl_crc_baseline{ 0 };
static std::atomic<uint32_t> sodium_crc_baseline{ 0 };


static inline void secure_zero(std::string& value) noexcept
{
    if (!value.empty()) {
        SecureZeroMemory(value.data(), value.size());
        value.clear();
    }
}

static inline void securewipe(std::string& value) noexcept
{
    secure_zero(value);
}

struct LocalHttpResources final {
    bool initialized = false;
    HTTP_SERVER_SESSION_ID session = 0;
    HTTP_URL_GROUP_ID group = 0;
    HANDLE queue = nullptr;
    LocalHttpResources() = default;
    LocalHttpResources(const LocalHttpResources&) = delete;
    LocalHttpResources& operator=(const LocalHttpResources&) = delete;
    ~LocalHttpResources() noexcept {
        if (group) HttpCloseUrlGroup(group);
        if (queue) HttpCloseRequestQueue(queue);
        if (session) HttpCloseServerSession(session);
        if (initialized) HttpTerminate(HTTP_INITIALIZE_SERVER, nullptr);
    }
};

struct ScopeWipe final {
    std::string* value;
    explicit ScopeWipe(std::string& v) noexcept : value(&v) {}
    ~ScopeWipe() noexcept { securewipe(*value); }
};

static std::string transform_saved_data(const std::string& input, bool encrypt)
{
    if (input.size() > MAXDWORD) throw KeyAuth::request_error("Local data exceeds the Windows protection limit.");
    DATA_BLOB in{static_cast<DWORD>(input.size()),
        reinterpret_cast<BYTE*>(const_cast<char*>(input.data()))};
    struct Output final {
        DATA_BLOB blob{};
        ~Output() {
            if (blob.pbData) {
                SecureZeroMemory(blob.pbData, blob.cbData);
                LocalFree(blob.pbData);
            }
        }
    } out;
    const BOOL ok = encrypt ?
        CryptProtectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out.blob) :
        CryptUnprotectData(&in, nullptr, nullptr, nullptr, nullptr, CRYPTPROTECT_UI_FORBIDDEN, &out.blob);
    if (!ok) throw KeyAuth::request_error("Windows could not protect or unlock local data for this account.");
    if (!out.blob.cbData) return {};
    return std::string(reinterpret_cast<const char*>(out.blob.pbData), out.blob.cbData);
}

std::string KeyAuth::api::protect_data(const std::string& data)
{
    constexpr size_t digest_size = crypto_generichash_BYTES;
    if (data.size() > MAXDWORD - 8 - digest_size)
        throw request_error("Local data exceeds the Windows protection limit.");
    if (sodium_init() < 0) throw request_error("Local data integrity initialization failed.");
    std::string plain("KA-DATA1", 8);
    ScopeWipe wipe_plain(plain);
    plain += data;
    const auto digest_offset = plain.size();
    plain.resize(digest_offset + digest_size);
    if (crypto_generichash(reinterpret_cast<unsigned char*>(plain.data() + digest_offset), digest_size,
        reinterpret_cast<const unsigned char*>(data.data()), data.size(), nullptr, 0) != 0)
        throw request_error("Local data integrity calculation failed.");
    std::string encrypted = transform_saved_data(plain, true);
    ScopeWipe wipe_encrypted(encrypted);
    const std::string prefix = "keyauth:dpapi:v1:";
    if (encrypted.size() > (std::string().max_size() - prefix.size()) / 2)
        throw request_error("Protected local data exceeds the string limit.");
    return prefix + bytes_to_hex(reinterpret_cast<const unsigned char*>(encrypted.data()), encrypted.size());
}

std::string KeyAuth::api::unprotect_data(const std::string& data)
{
    const std::string prefix = "keyauth:dpapi:v1:";
    if (data.compare(0, prefix.size(), prefix) != 0 || data.size() <= prefix.size())
        throw request_error("Unsupported protected local data format.");
    const auto encoded_size = data.size() - prefix.size();
    if (encoded_size % 2 || encoded_size / 2 > MAXDWORD)
        throw request_error("Invalid protected local data length.");
    if (sodium_init() < 0) throw request_error("Local data integrity initialization failed.");
    std::string encrypted(encoded_size / 2, '\0');
    ScopeWipe wipe_encrypted(encrypted);
    size_t decoded = 0;
    if (sodium_hex2bin(reinterpret_cast<unsigned char*>(encrypted.data()), encrypted.size(),
        data.data() + prefix.size(), encoded_size, nullptr, &decoded, nullptr) != 0 || decoded != encrypted.size())
        throw request_error("Invalid protected local data encoding.");
    std::string plain = transform_saved_data(encrypted, false);
    ScopeWipe wipe_plain(plain);
    constexpr size_t digest_size = crypto_generichash_BYTES;
    if (plain.size() < 8 + digest_size || plain.compare(0, 8, "KA-DATA1") != 0)
        throw request_error("Invalid protected local data envelope.");
    const auto size = plain.size() - 8 - digest_size;
    unsigned char digest[digest_size]{};
    if (crypto_generichash(digest, sizeof(digest),
        reinterpret_cast<const unsigned char*>(plain.data() + 8), size, nullptr, 0) != 0)
        throw request_error("Local data integrity calculation failed.");
    const bool valid = sodium_memcmp(digest, plain.data() + 8 + size, sizeof(digest)) == 0;
    SecureZeroMemory(digest, sizeof(digest));
    if (!valid) throw request_error("Protected local data failed its integrity check.");
    return plain.substr(8, size);
}

static uint64_t fnv1a64_bytes(const uint8_t* data, size_t len)
{
    uint64_t h = 0xcbf29ce484222325ULL;
    for (size_t i = 0; i < len; ++i) {
        h ^= static_cast<uint64_t>(data[i]);
        h *= 0x100000001b3ULL;
    }
    return h;
}

std::string KeyAuth::api::protect_field(const std::string& in, bool encrypt) const
{
    if (in.empty()) return {};
    std::string buffer;
    try {
        if (encrypt) {
            if (in.size() > MAXDWORD - sizeof(uint64_t) - CRYPTPROTECTMEMORY_BLOCK_SIZE)
                throw request_error("Protected string exceeds the Windows memory limit.");
            const uint64_t length = in.size();
            const size_t bytes = sizeof(length) + in.size();
            buffer.resize((bytes + CRYPTPROTECTMEMORY_BLOCK_SIZE - 1) /
                CRYPTPROTECTMEMORY_BLOCK_SIZE * CRYPTPROTECTMEMORY_BLOCK_SIZE, '\0');
            std::memcpy(buffer.data(), &length, sizeof(length));
            std::memcpy(buffer.data() + sizeof(length), in.data(), in.size());
            if (!CryptProtectMemory(buffer.data(), static_cast<DWORD>(buffer.size()),
                CRYPTPROTECTMEMORY_SAME_PROCESS))
                throw request_error("Windows memory protection failed.");
            return buffer;
        }
        if (in.size() > MAXDWORD || in.size() % CRYPTPROTECTMEMORY_BLOCK_SIZE != 0)
            throw request_error("Invalid protected string size.");
        buffer = in;
        if (!CryptUnprotectMemory(buffer.data(), static_cast<DWORD>(buffer.size()),
            CRYPTPROTECTMEMORY_SAME_PROCESS))
            throw request_error("Windows memory unprotection failed.");
        uint64_t length = 0;
        std::memcpy(&length, buffer.data(), sizeof(length));
        if (length > buffer.size() - sizeof(length))
            throw request_error("Invalid protected string length.");
        std::string result(buffer.data() + sizeof(length), static_cast<size_t>(length));
        secure_zero(buffer);
        return result;
    } catch (...) {
        secure_zero(buffer);
        throw;
    }
}

std::string KeyAuth::api::get_name() const {
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    return secure_strings_enabled_ ? protect_field(name_enc_, false) : name;
}
std::string KeyAuth::api::get_ownerid() const {
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    return secure_strings_enabled_ ? protect_field(ownerid_enc_, false) : ownerid;
}
std::string KeyAuth::api::get_version() const {
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    return secure_strings_enabled_ ? protect_field(version_enc_, false) : version;
}
std::string KeyAuth::api::get_url() const {
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    return secure_strings_enabled_ ? protect_field(url_enc_, false) : url;
}
std::string KeyAuth::api::get_path() const {
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    return secure_strings_enabled_ ? protect_field(path_enc_, false) : path;
}

void KeyAuth::api::enable_secure_strings(bool enable)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    if (enable) {
        if (secure_strings_enabled_)
            return;
        name_enc_ = protect_field(name, true);
        ownerid_enc_ = protect_field(ownerid, true);
        version_enc_ = protect_field(version, true);
        url_enc_ = protect_field(url, true);
        path_enc_ = protect_field(path, true);
        secure_zero(name);
        secure_zero(ownerid);
        secure_zero(version);
        secure_zero(url);
        secure_zero(path);
        secure_strings_enabled_ = true;
    } else {
        if (!secure_strings_enabled_)
            return;
        name = protect_field(name_enc_, false);
        ownerid = protect_field(ownerid_enc_, false);
        version = protect_field(version_enc_, false);
        url = protect_field(url_enc_, false);
        path = protect_field(path_enc_, false);
        secure_zero(name_enc_);
        secure_zero(ownerid_enc_);
        secure_zero(version_enc_);
        secure_zero(url_enc_);
        secure_zero(path_enc_);
        secure_strings_enabled_ = false;
    }
}

std::string KeyAuth::api::initialization_context() const
{
    return keyauth_detail::application_identity(get_ownerid(), get_name(), get_url());
}

void KeyAuth::api::bind_initialization_context()
{
    std::string identity = initialization_context();
    ScopeWipe wipe(identity);
    initialized_context_ = protect_field(identity, true);
}

bool KeyAuth::api::initialization_context_valid() const
{
    if (!initialized) return true;
    if (initialized_context_.empty()) return false;
    try {
        std::string expected = protect_field(initialized_context_, false);
        ScopeWipe wipe_expected(expected);
        std::string actual = initialization_context();
        ScopeWipe wipe_actual(actual);
        return expected == actual;
    } catch (const std::exception&) {
        return false;
    }
}

uint64_t KeyAuth::api::compute_auth_seal(uint64_t nonce, long long window) const
{
    const std::string hwid = utils::get_hwid();
    std::string material;
    ScopeWipe wipe_material(material);
    material.reserve(256);
    const auto append = [&material](const std::string& field) {
        material += std::to_string(field.size());
        material += ':';
        material += field;
    };
    append(get_ownerid());
    append(get_name());
    append(sessionid);
    append(user_data.username);
    append(hwid);
    append(std::to_string(GetCurrentProcessId()));
    append(std::to_string(reinterpret_cast<uintptr_t>(this)));
    append(std::to_string(nonce));
    append(std::to_string(window));
    append(enckey);
    append(initialized_context_);
    struct ScopedKey final {
        std::array<unsigned char, crypto_shorthash_KEYBYTES> value;
        ~ScopedKey() { SecureZeroMemory(value.data(), value.size()); }
    } key{auth_seal_key_};
    if (!CryptUnprotectMemory(key.value.data(), static_cast<DWORD>(key.value.size()),
        CRYPTPROTECTMEMORY_SAME_PROCESS))
        throw request_error("Windows authentication key protection failed.");
    uint64_t seal = 0;
    const int status = crypto_shorthash(reinterpret_cast<unsigned char*>(&seal),
        reinterpret_cast<const unsigned char*>(material.data()), material.size(), key.value.data());
    secure_zero(material);
    if (status != 0) throw request_error("Authentication state verification failed.");
    return seal;
}

void KeyAuth::api::store_auth_entitlements(bool reset_profile)
{
    nlohmann::json state;
    if (reset_profile) {
        state["subscriptions"] = nlohmann::json::array();
        for (const auto& sub : user_data.subscriptions)
            state["subscriptions"].push_back({{"name", sub.name}, {"expiry", sub.expiry}});
    } else {
        std::string plain = protect_field(enckey, false);
        ScopeWipe wipe_plain(plain);
        state = nlohmann::json::parse(plain);
    }
    state["paid"] = response.isPaid;
    std::string plain = state.dump();
    ScopeWipe wipe_plain(plain);
    std::string protected_state = protect_field(plain, true);
    secure_zero(enckey);
    enckey = std::move(protected_state);
}

bool KeyAuth::api::has_active_subscription() const
{
    try {
        std::string plain = protect_field(enckey, false);
        ScopeWipe wipe_plain(plain);
        const auto state = nlohmann::json::parse(plain);
        if (state.value("paid", false)) return true;
        const auto now = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        for (const auto& sub : state.at("subscriptions")) {
            const auto name = sub.at("name").get<std::string>();
            const auto expiry = sub.at("expiry").get<std::string>();
            if (name.empty() || expiry.empty()) continue;
            try {
                size_t consumed = 0;
                const auto expiration = std::stoll(expiry, &consumed);
                if (consumed == expiry.size() && expiration > now) return true;
            } catch (const std::invalid_argument&) {
            } catch (const std::out_of_range&) {
            }
        }
    } catch (const std::exception&) {
    }
    return false;
}

void KeyAuth::api::reset_auth_runtime()
{
    LoggedIn.store(false);
    auth_nonce_.store(0);
    secure_zero(enckey);
    SecureZeroMemory(auth_seal_key_.data(), auth_seal_key_.size());
    auth_window_.store(0);
    auth_seal_.store(0);
    response.success = false;
    response.isPaid = false;
}

void KeyAuth::api::mark_authenticated()
{
    try {
        uint64_t nonce = 0;
        do {
            if (BCryptGenRandom(nullptr, reinterpret_cast<PUCHAR>(&nonce), sizeof(nonce),
                BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
                reset_auth_runtime();
                throw request_error("Windows cryptographic random generation failed.");
            }
        } while (nonce == 0);
        if (BCryptGenRandom(nullptr, auth_seal_key_.data(), static_cast<ULONG>(auth_seal_key_.size()),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0) {
            reset_auth_runtime();
            throw request_error("Windows cryptographic random generation failed.");
        }
        if (!CryptProtectMemory(auth_seal_key_.data(), static_cast<DWORD>(auth_seal_key_.size()),
            CRYPTPROTECTMEMORY_SAME_PROCESS))
            throw request_error("Windows authentication key protection failed.");
        store_auth_entitlements(true);
        const auto window = keyauth_detail::auth_window_now();
        auth_nonce_.store(nonce);
        auth_window_.store(window);
        auth_seal_.store(compute_auth_seal(nonce, window));
        LoggedIn.store(true);
    } catch (...) {
        reset_auth_runtime();
        throw;
    }
}

void KeyAuth::api::refresh_auth_runtime()
{
    if (!LoggedIn.load())
        return;
    const uint64_t nonce = auth_nonce_.load();
    if (nonce == 0)
        return;
    const auto window = keyauth_detail::auth_window_now();
    store_auth_entitlements(false);
    auth_window_.store(window);
    auth_seal_.store(compute_auth_seal(nonce, window));
}

bool KeyAuth::api::authenticated(bool require_paid) const
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    return initialized && local_auth_valid(require_paid);
}

bool KeyAuth::api::local_auth_valid(bool require_paid, bool require_fresh) const
{
    if (!LoggedIn.load() || !initialization_context_valid())
        return false;
    if (sessionid.empty() || user_data.username.empty())
        return false;

    const uint64_t nonce = auth_nonce_.load();
    const long long sealed_window = auth_window_.load();
    const uint64_t sealed = auth_seal_.load();
    if (nonce == 0 || sealed_window == 0 || sealed == 0)
        return false;

    uint64_t expected = 0;
    try {
        expected = compute_auth_seal(nonce, sealed_window);
    } catch (const request_error&) {
        return false;
    }
    if (sodium_memcmp(&expected, &sealed, sizeof(sealed)) != 0)
        return false;
    const auto current_window = keyauth_detail::auth_window_now();
    if (require_fresh && !keyauth_detail::auth_window_fresh(sealed_window, current_window))
        return false;

    if (require_paid && !has_active_subscription())
        return false;

    return true;
}

static bool request_bypasses_local_auth(const std::string& data)
{
    const std::string type = data.substr(0, data.find('&'));
    return type == "type=init" || type == "type=login" || type == "type=license" ||
        type == "type=register" || type == "type=upgrade" || type == "type=forgot" ||
        type == "type=check" || type == "type=logout" ||
        keyauth_detail::email_request_uses_get(type.substr(5));
}

static std::string decode_pubkey_hex(const uint8_t* obf, size_t len, uint8_t key)
{
    std::string out;
    out.resize(len);
    for (size_t i = 0; i < len; ++i) {
        out[i] = static_cast<char>(obf[i] ^ key);
    }
    return out;
}

static std::string to_lower_ascii(std::string v)
{
    std::transform(v.begin(), v.end(), v.begin(),
        [](unsigned char c) { return keyauth_detail::ascii_lower(c); });
    return v;
}

static std::string wide_to_utf8(const wchar_t* w)
{
    if (!w)
        return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (needed <= 0)
        return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, w, -1, out.data(), needed, nullptr, nullptr);
    out.pop_back();
    return out;
}

static bool list_contains_any(const std::string& hay, const std::vector<std::string>& needles)
{
    for (const auto& n : needles) {
        if (hay.find(n) != std::string::npos)
            return true;
    }
    return false;
}

static bool url_points_to_loopback(const std::string& url)
{
    const std::string host = extract_host(url);
    if (host.empty())
        return false;
    std::string h = to_lower_ascii(host);
    if (h == "localhost" || h == "127.0.0.1" || h == "::1")
        return true;

    ADDRINFOA hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    ADDRINFOA* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return false;
    bool loopback = false;
    for (auto* p = res; p; p = p->ai_next) {
        if (p->ai_family == AF_INET) {
            auto* in = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            if ((ntohl(in->sin_addr.s_addr) & 0xFF000000u) == 0x7F000000u) {
                loopback = true;
                break;
            }
        } else if (p->ai_family == AF_INET6) {
            auto* in6 = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
            if (IN6_IS_ADDR_LOOPBACK(&in6->sin6_addr)) {
                loopback = true;
                break;
            }
        }
    }
    freeaddrinfo(res);
    return loopback;
}

static bool pubkey_memory_protect_ok()
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery(k_pubkey_obf1, &mbi, sizeof(mbi)))
        return false;
    const DWORD p = mbi.Protect;
    if (p & PAGE_GUARD)
        return false;
    if ((p & PAGE_READWRITE) || (p & PAGE_WRITECOPY) ||
        (p & PAGE_EXECUTE_READWRITE) || (p & PAGE_EXECUTE_WRITECOPY)) {
        return false;
    }
    if (pubkey_protect_ready.load(std::memory_order_relaxed)) {
        if (pubkey_protect_baseline != p)
            return false;
    }
    return true;
}

static std::string get_public_key_hex()
{
    // disabled: public key memory protection check. -nigel
    // if (!pubkey_memory_protect_ok()) {
    //     error(XorStr("public key memory protection tampered."));
    // }
    std::string a = decode_pubkey_hex(k_pubkey_obf1, sizeof(k_pubkey_obf1), k_pubkey_xor1);
    std::string b = decode_pubkey_hex(k_pubkey_obf2, sizeof(k_pubkey_obf2), k_pubkey_xor2);
    if (a != b) {
        error(XorStr("public key mismatch detected."));
    }
    const uint64_t h = fnv1a64_bytes(reinterpret_cast<const uint8_t*>(a.data()), a.size());
    pubkey_hash_seen.store(h, std::memory_order_relaxed);
    // disabled: public key integrity check. -nigel
    // if (h != k_pubkey_fnv1a) {
    //     error(XorStr("public key integrity failed."));
    // }
    return a;
}

static bool module_contains_ascii(const std::string& needle)
{
    if (needle.empty())
        return false;
    MODULEINFO mi{};
    if (!GetModuleInformation(GetCurrentProcess(), GetModuleHandleA(nullptr), &mi, sizeof(mi)))
        return false;
    const uint8_t* base = reinterpret_cast<const uint8_t*>(mi.lpBaseOfDll);
    const uint8_t* end = base + mi.SizeOfImage;
    const uint8_t* p = base;
    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(p, &mbi, sizeof(mbi)))
            break;
        const uint8_t* region = reinterpret_cast<const uint8_t*>(mbi.BaseAddress);
        const uint8_t* region_end = region + mbi.RegionSize;
        if (region_end > end)
            region_end = end;
        const DWORD protect = mbi.Protect;
        const bool readable = (protect & PAGE_READONLY) || (protect & PAGE_READWRITE) ||
            (protect & PAGE_EXECUTE_READ) || (protect & PAGE_EXECUTE_READWRITE) ||
            (protect & PAGE_WRITECOPY) || (protect & PAGE_EXECUTE_WRITECOPY);
        if (mbi.State == MEM_COMMIT && readable) {
            const char* cbegin = reinterpret_cast<const char*>(region);
            const char* cend = reinterpret_cast<const char*>(region_end);
            auto it = std::search(cbegin, cend, needle.begin(), needle.end());
            if (it != cend)
                return true;
        }
        p = region_end;
    }
    return false;
}

void KeyAuth::api::init()
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    if (initialized) {
        if (!initialization_context_valid()) throw request_error("Application configuration changed after initialization. Create a new API instance.");
        return;
    }
    secure_zero(initialized_context_);
    static const CURLcode curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
    if (curl_init_result != CURLE_OK) throw request_error("CURL global initialization failed.");
    (void)get_public_key_hex();
    if (get_ownerid().length() != 10)
    {
        MessageBoxA(0, XorStr("Application Not Setup Correctly. Please Watch Video Linked in main.cpp").c_str(), NULL, MB_ICONERROR);
        KA_EXIT(0);
    }

    std::string hash = checksum();
    auto data =
        XorStr("type=init") +
        XorStr("&ver=") + curl_escape(nullptr, get_version()) +
        XorStr("&hash=") + curl_escape(nullptr, hash) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    // to ensure people removed secret from main.cpp (some people will forget to)
    const std::string resolved_path = get_path();
    if (resolved_path.find("https") != std::string::npos) {
        MessageBoxA(0, XorStr("You forgot to remove \"secret\" from main.cpp. Copy details from ").c_str(), NULL, MB_ICONERROR);
        KA_EXIT(0);
    }

    if (!resolved_path.empty()) {

        const auto token_path = keyauth_detail::native_file_path(resolved_path);
        if (!std::filesystem::exists(token_path)) {
            MessageBoxA(0, XorStr("File not found. Please make sure the file exists.").c_str(), NULL, MB_ICONERROR);
            KA_EXIT(0);
        }
        //get the contents of the file
        std::ifstream file(token_path);
        if (!file) {
            throw request_error("Cannot open API token file.");
        }
        std::string token;
        std::string thash;
        ScopeWipe wipe_token(token);
        if (!std::getline(file, token)) {
            throw request_error("Cannot read API token file.");
        }

        thash = keyauth_detail::file_md5(token_path);

        data += XorStr("&token=").c_str() + curl_escape(nullptr, token);
        data += XorStr("&thash=").c_str() + curl_escape(nullptr, thash);
    }

    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    if (response == XorStr("KeyAuth_Invalid").c_str()) {
        MessageBoxA(0, XorStr("Application not found. Please copy strings directly from dashboard.").c_str(), NULL, MB_ICONERROR);
        KA_EXIT(0);
    }

    std::hash<int> hasher;
    int expectedHash = hasher(42);

    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);

        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        load_response_data(json);

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            if (json[(XorStr("success"))])
            {
                if (json[(XorStr("newSession"))]) {
                    Sleep(100);
                }
                sessionid = json[(XorStr("sessionid"))];
                bind_initialization_context();
                load_app_data(json[(XorStr("appinfo"))]);
                initialized = true;
            }
            else if (json[(XorStr("message"))] == XorStr("invalidver"))
            {
                std::string dl = json[(XorStr("download"))];
                api::app_data.downloadLink = json[XorStr("download")];
                if (dl == "")
                {
                    MessageBoxA(0, XorStr("Version in the loader does match the one on the dashboard, and the download link on dashboard is blank.\n\nTo fix this, either fix the loader so it matches the version on the dashboard. Or if you intended for it to have different versions, update the download link on dashboard so it will auto-update correctly.").c_str(), NULL, MB_ICONERROR);
                }
                else
                {
                    ShellExecuteA(0, XorStr("open").c_str(), dl.c_str(), 0, 0, SW_SHOWNORMAL);
                }
                KA_EXIT(0);
            }
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}

size_t write_callback(void* contents, size_t size, size_t nmemb, void* userp) noexcept {
    if (size && nmemb > SIZE_MAX / size) return 0;
    const size_t bytes = size * nmemb;
    try {
        return keyauth_detail::append_response(*static_cast<keyauth_detail::ResponseBuffer*>(userp),
            static_cast<char*>(contents), bytes) ? bytes : 0;
    } catch (...) { return 0; }
}

size_t header_callback(char* buffer, size_t size, size_t nitems, void* userdata) noexcept {
    if (size && nitems > SIZE_MAX / size) return 0;
    const size_t bytes = size * nitems;
    try {
        return keyauth_detail::consume_header(*static_cast<SignatureHeaders*>(userdata),
                                              std::string(buffer, bytes)) ? bytes : 0;
    } catch (...) { return 0; }
}


void KeyAuth::api::login(std::string username, std::string password, std::string code)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_user(username);
    ScopeWipe wipe_pass(password);
    ScopeWipe wipe_code(code);

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=login") +
        XorStr("&username=") + curl_escape(nullptr, username) +
        XorStr("&pass=") + curl_escape(nullptr, password) +
        XorStr("&code=") + curl_escape(nullptr, code) +
        XorStr("&hwid=") + curl_escape(nullptr, hwid) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);
    //std::cout << "[DEBUG] Login response: " << response << std::endl;
    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        //std::cout << "[DEBUG] Login response:" << response << std::endl;

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            if (json[(XorStr("success"))])
                load_user_data(json[(XorStr("info"))]);
            else
                reset_auth_runtime();

            if (json[XorStr("success")].get<bool>()) {
                mark_authenticated();
                start_heartbeat();
            } else {
                reset_auth_runtime();
            }
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}


nlohmann::json KeyAuth::api::email_reply(std::string data)
{
    ScopeWipe wipe(data);
    auto raw = req(data, get_url());
    ScopeWipe wipe_raw(raw);
    auto reply = nlohmann::json::parse(raw, nullptr, false);
    try {
        keyauth_detail::validate_api_reply(reply, get_ownerid());
    } catch (const std::exception& e) {
        throw request_error(e.what());
    }
    load_response_data(reply);
    return reply;
}

bool KeyAuth::api::finish_email_login(const nlohmann::json& reply, const std::string& email)
{
    reset_auth_runtime();
    user_data = {};
    load_response_data(reply);
    if (!response.success) return false;
    try {
        if (reply.contains("info")) {
            if (!reply["info"].is_object()) throw request_error("Invalid login profile.");
            load_user_data(reply["info"]);
        }
        if (user_data.username.empty()) user_data.username = email;
        const auto status = email_reply("type=check&sessionid=" + curl_escape(nullptr, sessionid) +
            "&name=" + curl_escape(nullptr, get_name()) + "&ownerid=" + curl_escape(nullptr, get_ownerid()));
        if (!response.success) {
            user_data = {};
            return false;
        }
        response.message = reply["message"].get<std::string>();
        mark_authenticated();
        start_heartbeat();
        magic_link_email_.clear();
        return true;
    } catch (...) {
        reset_auth_runtime();
        user_data = {};
        throw;
    }
}

void KeyAuth::api::login_email(std::string email, std::string password, std::string code)
{
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_email(email), wipe_password(password), wipe_code(code);
    reset_auth_runtime();
    user_data = {};
    magic_link_email_.clear();
    const auto reply = email_reply(keyauth_detail::email_request("loginEmail", email, password, code,
        sessionid, get_name(), get_ownerid(), utils::get_hwid()));
    finish_email_login(reply, email);
}

void KeyAuth::api::email_otp_send(std::string email)
{
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_email(email);
    reset_auth_runtime();
    user_data = {};
    magic_link_email_.clear();
    email_reply(keyauth_detail::email_request("emailOTPSend", email, "", "", sessionid,
        get_name(), get_ownerid(), ""));
}

void KeyAuth::api::email_otp_verify(std::string email, std::string code)
{
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_email(email), wipe_code(code);
    reset_auth_runtime();
    user_data = {};
    const auto reply = email_reply(keyauth_detail::email_request("emailOTPVerify", email, "", code,
        sessionid, get_name(), get_ownerid(), utils::get_hwid()));
    finish_email_login(reply, email);
}

void KeyAuth::api::magic_link_send(std::string email)
{
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_email(email);
    reset_auth_runtime();
    user_data = {};
    magic_link_email_.clear();
    email_reply(keyauth_detail::email_request("magicLinkSend", email, "", "", sessionid,
        get_name(), get_ownerid(), utils::get_hwid()));
    if (response.success) {
        magic_link_email_ = email;
        magic_link_started_ = std::chrono::steady_clock::now();
        magic_link_last_check_ = {};
    }
}

bool KeyAuth::api::magic_link_pending() const
{
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    return !magic_link_email_.empty() &&
        std::chrono::steady_clock::now() - magic_link_started_ < std::chrono::minutes(15);
}

bool KeyAuth::api::magic_link_check()
{
    std::lock_guard<std::recursive_mutex> lock(api_mutex_);
    checkInit();
    response.success = false;
    if (!magic_link_pending()) {
        magic_link_email_.clear();
        response.message = "No active magic link request, or the link has expired.";
        return false;
    }
    const auto now = std::chrono::steady_clock::now();
    if (now - magic_link_last_check_ < std::chrono::seconds(3)) {
        response.message = "Waiting for magic link approval.";
        return false;
    }
    magic_link_last_check_ = now;
    const auto email = magic_link_email_;
    const auto reply = email_reply(keyauth_detail::email_request("magicLinkCheck", email, "", "",
        sessionid, get_name(), get_ownerid(), utils::get_hwid()));
    if (!keyauth_detail::magic_link_approved(reply)) {
        response.success = false;
        return false;
    }
    return finish_email_login(reply, email);
}

void KeyAuth::api::chatget(std::string channel)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_channel(channel);

    auto data =
        XorStr("type=chatget") +
        XorStr("&channel=") + curl_escape(nullptr, channel) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);
    auto json = response_decoder.parse(response);
    load_channel_data(json);
}

bool KeyAuth::api::chatsend(std::string message, std::string channel)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_message(message);
    ScopeWipe wipe_channel(channel);

    auto data =
        XorStr("type=chatsend") +
        XorStr("&message=") + curl_escape(nullptr, message) +
        XorStr("&channel=") + curl_escape(nullptr, channel) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);
    auto json = response_decoder.parse(response);
    load_response_data(json);
    return json[XorStr("success")];
}

void KeyAuth::api::changeUsername(std::string newusername)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_user(newusername);

    auto data =
        XorStr("type=changeUsername") +
        XorStr("&newUsername=") + curl_escape(nullptr, newusername) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);
    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {

        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}

KeyAuth::api::Tfa& KeyAuth::api::enable2fa(std::string code)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();

   KeyAuth::api::activate = true;

    auto data =
        XorStr("type=2faenable") +
        XorStr("&code=") + curl_escape(nullptr, code) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);
    auto json = response_decoder.parse(response);

    if (json.contains("2fa")) {

        api::response.success = json[XorStr("success")];
        api::tfa.secret = json["2fa"]["secret_code"];
        api::tfa.link = json["2fa"]["QRCode"];
    }
    else {
        load_response_data(json);
    }
    
    return api::tfa;
}

KeyAuth::api::Tfa& KeyAuth::api::disable2fa(std::string code)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    
    KeyAuth::api::activate = false;

    if (code.empty()) {
        return this->tfa.handleInput(*this);
    }


    auto data =
        XorStr("type=2fadisable") +
        XorStr("&code=") + curl_escape(nullptr, code) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    auto json = response_decoder.parse(response);

    load_response_data(json);

    return api::tfa;
}

void KeyAuth::api::Tfa::QrCode() {
    auto qrcode = QrToPng("QRCode.png", 300, 3, KeyAuth::api::Tfa::link, true, qrcodegen::QrCode::Ecc::MEDIUM);
    qrcode.writeToPNG();
}

KeyAuth::api::Tfa& KeyAuth::api::Tfa::handleInput(KeyAuth::api& instance) {

    if (instance.activate) {
        QrCode();

        ShellExecuteA(0, XorStr("open").c_str(), XorStr("QRCode.png").c_str(), 0, 0, SW_SHOWNORMAL);

        system("cls");
        std::cout << XorStr("Press enter when you have scanned the QR code");
        std::cin.get();

        // remove the QR code
        remove("QRCode.png");

        system("cls");

        std::cout << XorStr("Enter the code: ");

        std::string code;
        std::cin >> code;

        instance.enable2fa(code);
    }
    else {

        LI_FN(system)(XorStr("cls").c_str());

        std::cout << XorStr("Enter the code to disable 2FA: ");

		std::string code;
		std::cin >> code;

		instance.disable2fa(code);
	}
    return *this;
}

void KeyAuth::api::web_login()
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();

    // from https://perpetualprogrammers.wordpress.com/2016/05/22/the-http-server-api/

    // Initialize the API.
    LocalHttpResources listener;
    ULONG result = 0;
    HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
    result = HttpInitialize(version, HTTP_INITIALIZE_SERVER, 0);
    listener.initialized = result == NO_ERROR;

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "The Flags parameter contains an unsupported value.", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }
    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for Initialize", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    // Create server session.
    auto& serverSessionId = listener.session;
    result = HttpCreateServerSession(version, &serverSessionId, 0);

    if (result == ERROR_REVISION_MISMATCH) {
        MessageBoxA(NULL, "Version for session invalid", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "pServerSessionId parameter is null", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateServerSession", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    // Create URL group.
    auto& groupId = listener.group;
    result = HttpCreateUrlGroup(serverSessionId, &groupId, 0);

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "Url group create parameter error", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateUrlGroup", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    // Create request queue.
    auto& requestQueueHandle = listener.queue;
    result = HttpCreateRequestQueue(version, NULL, NULL, 0, &requestQueueHandle);

    if (result == ERROR_REVISION_MISMATCH) {
        MessageBoxA(NULL, "Wrong version", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, "Byte length exceeded", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, "pName already used", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result == ERROR_ACCESS_DENIED) {
        MessageBoxA(NULL, "queue access denied", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result == ERROR_DLL_INIT_FAILED) {
        MessageBoxA(NULL, "Initialize not called", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, "System error for HttpCreateRequestQueue", "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    // Attach request queue to URL group.
    HTTP_BINDING_INFO info{};
    info.Flags.Present = 1;
    info.RequestQueueHandle = requestQueueHandle;
    result = HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &info, sizeof(info));

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, XorStr("Invalid parameter").c_str(), "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, XorStr("System error for HttpSetUrlGroupProperty").c_str(), "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    // Add URLs to URL group.
    PCWSTR url = L"http://localhost:1337/handshake";
    result = HttpAddUrlToUrlGroup(groupId, url, 0, 0);

    if (result == ERROR_ACCESS_DENIED) {
        MessageBoxA(NULL, XorStr("No permissions to run web server").c_str(), "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result == ERROR_ALREADY_EXISTS) {
        MessageBoxA(NULL, XorStr("You are running this program already").c_str(), "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result == ERROR_INVALID_PARAMETER) {
        MessageBoxA(NULL, XorStr("ERROR_INVALID_PARAMETER for HttpAddUrlToUrlGroup").c_str(), "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result == ERROR_SHARING_VIOLATION) {
        MessageBoxA(NULL, XorStr("Another program is using the webserver. Close Razer Chroma mouse software if you use that. Try to restart computer.").c_str(), "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    if (result != NO_ERROR) {
        MessageBoxA(NULL, XorStr("System error for HttpAddUrlToUrlGroup").c_str(), "Error", MB_ICONEXCLAMATION);
        KA_EXIT(0);
    }

    // Announce that it is running.
    // wprintf(L"Listening. Please submit requests to: %s\n", url);

    // req to: http://localhost:1337/handshake?user=mak&token=2f3e9eccc22ee583cf7bad86c751d865
    bool going = true;
    while (going == true)
    {
        // Wait for a request.
        HTTP_REQUEST_ID requestId = 0;
        HTTP_SET_NULL_ID(&requestId);
        int bufferSize = 64 * 1024;
        int requestSize = sizeof(HTTP_REQUEST) + bufferSize;
        auto buffer = std::make_unique<BYTE[]>(requestSize);
        PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer.get();
        RtlZeroMemory(buffer.get(), requestSize);
        ULONG bytesReturned = 0;
        result = HttpReceiveHttpRequest(
            requestQueueHandle,
            requestId,
            HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
            pRequest,
            requestSize,
            &bytesReturned,
            NULL
        );
        if (result == ERROR_MORE_DATA) {
            if (pRequest->RequestId) HttpCancelHttpRequest(requestQueueHandle, pRequest->RequestId, nullptr);
            continue;
        }
        if (result == ERROR_CONNECTION_INVALID || result == ERROR_HANDLE_EOF) continue;
        if (result != NO_ERROR)
            throw request_error("Local HTTP request reception failed (code " + std::to_string(result) + ").");

        // Display some information about the request.
        // wprintf(L"Full URL: %ws\n", pRequest->CookedUrl.pFullUrl);
        // wprintf(L"    Path: %ws\n", pRequest->CookedUrl.pAbsPath);
        // wprintf(L"    Query: %ws\n", pRequest->CookedUrl.pQueryString);

        std::wstring ws;
        try {
            ws = keyauth_detail::bounded_http_query(pRequest->CookedUrl.pQueryString,
                pRequest->CookedUrl.QueryStringLength, buffer.get(), requestSize);
        } catch (const std::invalid_argument&) {
            HttpCancelHttpRequest(requestQueueHandle, pRequest->RequestId, nullptr);
            continue;
        }
        std::string myVarS = std::string(ws.begin(), ws.end());
        ScopeWipe wipe_query(myVarS);
        std::string user = get_str_between_two_str(myVarS, "?user=", "&");
        std::string token = get_str_between_two_str(myVarS, "&token=", "");
        ScopeWipe wipe_token(token);
        ScopeWipe wipe_user(user);

        // std::cout << get_str_between_two_str(CW2A(pRequest->CookedUrl.pQueryString), "?", "&") << std::endl;

        // break if preflight request from browser
        if (pRequest->Verb == HttpVerbOPTIONS)
        {
            // Respond to the request.
            HTTP_RESPONSE response;
            RtlZeroMemory(&response, sizeof(response));

            response.StatusCode = 200;
            response.pReason = "OK";
            response.ReasonLength = (USHORT)strlen(response.pReason);

            // https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
            HTTP_UNKNOWN_HEADER  accessControlHeader;
            const char testCustomHeader[] = "Access-Control-Allow-Origin";
            const char testCustomHeaderVal[] = "*";
            accessControlHeader.pName = testCustomHeader;
            accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
            accessControlHeader.pRawValue = testCustomHeaderVal;
            accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
            response.Headers.pUnknownHeaders = &accessControlHeader;
            response.Headers.UnknownHeaderCount = 1;
            // Add an entity chunk to the response.
            // PSTR pEntityString = "Hello from C++";
            HTTP_DATA_CHUNK dataChunk;
            dataChunk.DataChunkType = HttpDataChunkFromMemory;

            result = HttpSendHttpResponse(
                requestQueueHandle,
                pRequest->RequestId,
                0,
                &response,
                NULL,
                NULL,   // &bytesSent (optional)
                NULL,
                0,
                NULL,
                NULL
            );

            continue;
        }

        if (user.empty() || token.empty()) {
            HttpCancelHttpRequest(requestQueueHandle, pRequest->RequestId, nullptr);
            continue;
        }

        // keyauth request
        std::string hwid = utils::get_hwid();
        auto data =
            XorStr("type=login") +
            XorStr("&username=") + curl_escape(nullptr, user) +
            XorStr("&token=") + curl_escape(nullptr, token) +
            XorStr("&hwid=") + curl_escape(nullptr, hwid) +
            XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
            XorStr("&name=") + curl_escape(nullptr, get_name()) +
            XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
        ScopeWipe wipe_request_data(data);
        auto resp = req(data, get_url());
        ScopeWipe wipe_response_body(resp);

        std::hash<int> hasher;
        int expectedHash = hasher(42);
        int result = VerifyPayload(signature, signatureTimestamp, resp);
        if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
        {
            auto json = response_decoder.parse(resp);
            if (json[(XorStr("ownerid"))] != get_ownerid()) {
                KA_EXIT(8);
            }

            std::string message = json[(XorStr("message"))];

            std::hash<int> hasher;
            size_t expectedHash = hasher(68);
            size_t resultCode = hasher(json[(XorStr("code"))]);

            if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
                load_response_data(json);
                if (json[XorStr("success")].get<bool>()) {
                    load_user_data(json[XorStr("info")]);
                    mark_authenticated();
                    start_heartbeat();
                } else {
                    reset_auth_runtime();
                }

                // Respond to the request.
                HTTP_RESPONSE response;
                RtlZeroMemory(&response, sizeof(response));

                std::string response_reason;
                bool success = true;
                if (json[(XorStr("success"))])
                {
                    load_user_data(json[(XorStr("info"))]);

                    response.StatusCode = 420;
                    response.pReason = "SHEESH";
                    response.ReasonLength = (USHORT)strlen(response.pReason);
                }
                else
                {
                    response.StatusCode = 200;
                    response_reason = keyauth_detail::http_reason(json.at("message").get<std::string>());
                    response.pReason = response_reason.c_str();
                    response.ReasonLength = (USHORT)strlen(response.pReason);
                    success = false;
                }
                // end keyauth request

                // https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
                HTTP_UNKNOWN_HEADER  accessControlHeader;
                const char testCustomHeader[] = "Access-Control-Allow-Origin";
                const char testCustomHeaderVal[] = "*";
                accessControlHeader.pName = testCustomHeader;
                accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
                accessControlHeader.pRawValue = testCustomHeaderVal;
                accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
                response.Headers.pUnknownHeaders = &accessControlHeader;
                response.Headers.UnknownHeaderCount = 1;
                // Add an entity chunk to the response.
                // PSTR pEntityString = "Hello from C++";
                HTTP_DATA_CHUNK dataChunk;
                dataChunk.DataChunkType = HttpDataChunkFromMemory;

                result = HttpSendHttpResponse(
                    requestQueueHandle,
                    pRequest->RequestId,
                    0,
                    &response,
                    NULL,
                    NULL,   // &bytesSent (optional)
                    NULL,
                    0,
                    NULL,
                    NULL
                );

                if (result == NO_ERROR) {
                    going = false;
                }

                if (!success)
                    KA_EXIT(0);
            }
            else {
                KA_EXIT(9);
            }
        }
        else {
            KA_EXIT(7);
        }
    }
}

void KeyAuth::api::button(std::string button)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_button(button);

    // from https://perpetualprogrammers.wordpress.com/2016/05/22/the-http-server-api/

    // Initialize the API.
    LocalHttpResources listener;
    ULONG result = 0;
    HTTPAPI_VERSION version = HTTPAPI_VERSION_2;
    result = HttpInitialize(version, HTTP_INITIALIZE_SERVER, 0);
    listener.initialized = result == NO_ERROR;
    if (result != NO_ERROR) throw request_error("Local HTTP listener setup failed (code " + std::to_string(result) + ").");

    // Create server session.
    auto& serverSessionId = listener.session;
    result = HttpCreateServerSession(version, &serverSessionId, 0);
    if (result != NO_ERROR) throw request_error("Local HTTP listener setup failed (code " + std::to_string(result) + ").");

    // Create URL group.
    auto& groupId = listener.group;
    result = HttpCreateUrlGroup(serverSessionId, &groupId, 0);
    if (result != NO_ERROR) throw request_error("Local HTTP listener setup failed (code " + std::to_string(result) + ").");

    // Create request queue.
    auto& requestQueueHandle = listener.queue;
    result = HttpCreateRequestQueue(version, NULL, NULL, 0, &requestQueueHandle);
    if (result != NO_ERROR) throw request_error("Local HTTP listener setup failed (code " + std::to_string(result) + ").");

    // Attach request queue to URL group.
    HTTP_BINDING_INFO info{};
    info.Flags.Present = 1;
    info.RequestQueueHandle = requestQueueHandle;
    result = HttpSetUrlGroupProperty(groupId, HttpServerBindingProperty, &info, sizeof(info));
    if (result != NO_ERROR) throw request_error("Local HTTP listener setup failed (code " + std::to_string(result) + ").");

    // Add URLs to URL group.
    std::wstring output;
    output = std::wstring(button.begin(), button.end());
    output = std::wstring(L"http://localhost:1337/") + output;
    PCWSTR url = output.c_str();
    result = HttpAddUrlToUrlGroup(groupId, url, 0, 0);
    if (result != NO_ERROR) throw request_error("Local HTTP listener setup failed (code " + std::to_string(result) + ").");

    // Announce that it is running.
    // wprintf(L"Listening. Please submit requests to: %s\n", url);

    // req to: http://localhost:1337/buttonvaluehere
    bool going = true;
    while (going == true)
    {
        // Wait for a request.
        HTTP_REQUEST_ID requestId = 0;
        HTTP_SET_NULL_ID(&requestId);
        int bufferSize = 64 * 1024;
        int requestSize = sizeof(HTTP_REQUEST) + bufferSize;
        auto buffer = std::make_unique<BYTE[]>(requestSize);
        PHTTP_REQUEST pRequest = (PHTTP_REQUEST)buffer.get();
        RtlZeroMemory(buffer.get(), requestSize);
        ULONG bytesReturned = 0;
        result = HttpReceiveHttpRequest(
            requestQueueHandle,
            requestId,
            HTTP_RECEIVE_REQUEST_FLAG_COPY_BODY,
            pRequest,
            requestSize,
            &bytesReturned,
            NULL
        );
        if (result == ERROR_MORE_DATA) {
            if (pRequest->RequestId) HttpCancelHttpRequest(requestQueueHandle, pRequest->RequestId, nullptr);
            continue;
        }
        if (result == ERROR_CONNECTION_INVALID || result == ERROR_HANDLE_EOF) continue;
        if (result != NO_ERROR)
            throw request_error("Local HTTP request reception failed (code " + std::to_string(result) + ").");

        going = false;

        // Display some information about the request.
        // wprintf(L"Full URL: %ws\n", pRequest->CookedUrl.pFullUrl);
        // wprintf(L"    Path: %ws\n", pRequest->CookedUrl.pAbsPath);
        // wprintf(L"    Query: %ws\n", pRequest->CookedUrl.pQueryString);

        // std::cout << get_str_between_two_str(CW2A(pRequest->CookedUrl.pQueryString), "?", "&") << std::endl;

        // Break from the loop if it's the poison pill (a DELETE request).
        // if (pRequest->Verb == HttpVerbDELETE)
        // {
        //     wprintf(L"Asked to stop.\n");
        //     break;
        // }

        // Respond to the request.
        HTTP_RESPONSE response;
        RtlZeroMemory(&response, sizeof(response));
        response.StatusCode = 420;
        response.pReason = "SHEESH";
        response.ReasonLength = (USHORT)strlen(response.pReason);

        // https://social.msdn.microsoft.com/Forums/vstudio/en-US/6d468747-2221-4f4a-9156-f98f355a9c08/using-httph-to-set-up-an-https-server-that-is-queried-by-a-client-that-uses-cross-origin-requests?forum=vcgeneral
        HTTP_UNKNOWN_HEADER  accessControlHeader;
        const char testCustomHeader[] = "Access-Control-Allow-Origin";
        const char testCustomHeaderVal[] = "*";
        accessControlHeader.pName = testCustomHeader;
        accessControlHeader.NameLength = _countof(testCustomHeader) - 1;
        accessControlHeader.pRawValue = testCustomHeaderVal;
        accessControlHeader.RawValueLength = _countof(testCustomHeaderVal) - 1;
        response.Headers.pUnknownHeaders = &accessControlHeader;
        response.Headers.UnknownHeaderCount = 1;
        // Add an entity chunk to the response.
        // PSTR pEntityString = "Hello from C++";
        HTTP_DATA_CHUNK dataChunk;
        dataChunk.DataChunkType = HttpDataChunkFromMemory;

        result = HttpSendHttpResponse(
            requestQueueHandle,
            pRequest->RequestId,
            0,
            &response,
            NULL,
            NULL,   // &bytesSent (optional)
            NULL,
            0,
            NULL,
            NULL
        );

    }
}

void KeyAuth::api::regstr(std::string username, std::string password, std::string key, std::string email) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_user(username);
    ScopeWipe wipe_pass(password);
    ScopeWipe wipe_key(key);
    ScopeWipe wipe_email(email);

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=register") +
        XorStr("&username=") + curl_escape(nullptr, username) +
        XorStr("&pass=") + curl_escape(nullptr, password) +
        XorStr("&key=") + curl_escape(nullptr, key) +
        XorStr("&email=") + curl_escape(nullptr, email) +
        XorStr("&hwid=") + curl_escape(nullptr, hwid) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            load_response_data(json);
            if (json[(XorStr("success"))])
                load_user_data(json[(XorStr("info"))]);
            else
                reset_auth_runtime();

            if (json[XorStr("success")].get<bool>()) {
                mark_authenticated();
                start_heartbeat();
            } else {
                reset_auth_runtime();
            }
        }
        else {
            KA_EXIT(9);
        }
    }
    else
    {
        KA_EXIT(7);
    }
}

void KeyAuth::api::upgrade(std::string username, std::string key) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_user(username);
    ScopeWipe wipe_key(key);

    auto data =
        XorStr("type=upgrade") +
        XorStr("&username=") + curl_escape(nullptr, username) +
        XorStr("&key=") + curl_escape(nullptr, key) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            json[(XorStr("success"))] = false;
            load_response_data(json);
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}

std::string generate_random_number() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<> dist_length(5, 10); // Random length between 5 and 10 digits
    std::uniform_int_distribution<> dist_digit(0, 9);   // Random digit

    int length = dist_length(gen);
    std::string random_number;
    for (int i = 0; i < length; ++i) {
        random_number += std::to_string(dist_digit(gen));
    }
    return random_number;
}

void KeyAuth::api::license(std::string key, std::string code) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_key(key);
    ScopeWipe wipe_code(code);

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=license") +
        XorStr("&key=") + curl_escape(nullptr, key) +
        XorStr("&code=") + curl_escape(nullptr, code) +
        XorStr("&hwid=") + curl_escape(nullptr, hwid) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            if (json[(XorStr("success"))])
                load_user_data(json[(XorStr("info"))]);
            else
                reset_auth_runtime();

            if (json[XorStr("success")].get<bool>()) {
                mark_authenticated();
                start_heartbeat();
            } else {
                reset_auth_runtime();
            }
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}

void KeyAuth::api::setvar(std::string var, std::string vardata) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_var(var);
    ScopeWipe wipe_data(vardata);

    auto data =
        XorStr("type=setvar") +
        XorStr("&var=") + curl_escape(nullptr, var) +
        XorStr("&data=") + curl_escape(nullptr, vardata) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);
    auto json = response_decoder.parse(response);
    load_response_data(json);
}

std::string KeyAuth::api::getvar(std::string var) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_var(var);

    auto data =
        XorStr("type=getvar") +
        XorStr("&var=") + curl_escape(nullptr, var) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            return !json[(XorStr("response"))].is_null() ? json[(XorStr("response"))] : XorStr("");
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}

void KeyAuth::api::ban(std::string reason) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_reason(reason);

    auto data =
        XorStr("type=ban") +
        XorStr("&reason=") + curl_escape(nullptr, reason) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
        }
        else {
            KA_EXIT(9);
        }
    }
    else
    {
        KA_EXIT(7);
    }
}

bool KeyAuth::api::checkblack() {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();

    std::string hwid = utils::get_hwid();
    auto data =
        XorStr("type=checkblacklist") +
        XorStr("&hwid=") + curl_escape(nullptr, hwid) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            return json[XorStr("success")];
        }
        KA_EXIT(9);
    }
    else {
        KA_EXIT(7);
    }
}

void KeyAuth::api::check(bool check_paid) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();

    if (LoggedIn.load() && !local_auth_valid(false, false)) {
        reset_auth_runtime();
        return;
    }

    auto data =
        XorStr("type=check") +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    std::string endpoint = get_url();
    if (check_paid) {
        endpoint += (endpoint.find('?') == std::string::npos ? "?" : "&");
        endpoint += "check_paid=1";
    }

    auto response = req(data, endpoint);
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            if (json[(XorStr("success"))]) {
                refresh_auth_runtime();
            }
            else {
                reset_auth_runtime();
            }
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        reset_auth_runtime();
        KA_EXIT(7);
    }
}

std::string KeyAuth::api::var(std::string varid) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();

    auto data =
        XorStr("type=var") +
        XorStr("&varid=") + curl_escape(nullptr, varid) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            load_response_data(json);
            return json[(XorStr("message"))];
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}

void KeyAuth::api::log(std::string message) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_message(message);

    wchar_t acUserName[UNLEN + 1]{};
    DWORD nUserName = static_cast<DWORD>(std::size(acUserName));
    std::string UsernamePC;
    if (GetUserNameW(acUserName, &nUserName) && nUserName > 0 && nUserName <= std::size(acUserName))
        UsernamePC = wide_to_utf8(acUserName);
    SecureZeroMemory(acUserName, sizeof(acUserName));
    ScopeWipe wipe_pcuser(UsernamePC);

    auto data =
        XorStr("type=log") +
        XorStr("&pcuser=") + curl_escape(nullptr, UsernamePC) +
        XorStr("&message=") + curl_escape(nullptr, message) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    req(data, get_url());
}

std::vector<unsigned char> KeyAuth::api::download(std::string fileid) {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_fileid(fileid);

    auto data =
        XorStr("type=file") +
        XorStr("&fileid=") + curl_escape(nullptr, fileid) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    auto reply = req(data, get_url());
    ScopeWipe wipe_reply(reply);
    auto json = nlohmann::json::parse(reply, nullptr, false);
    if (json.is_discarded() || !json.is_object()) {
        response.success = false;
        throw request_error("Invalid JSON response from download endpoint.");
    }
    load_response_data(json);
    if (!response.success) return {};
    if (!json.contains("contents") || !json["contents"].is_string()) {
        response.success = false;
        throw request_error("Download response has no contents field.");
    }
    auto& contents = json["contents"].get_ref<std::string&>();
    ScopeWipe wipe_contents(contents);
    if (contents.size() % 2 || (!contents.empty() && !is_hex_string(contents))) {
        response.success = false;
        throw request_error("Download contents are not valid hexadecimal data.");
    }
    return keyauth_detail::decode_download(contents);
}


std::string KeyAuth::api::webhook(std::string id, std::string params, std::string body, std::string contenttype)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_id(id);
    ScopeWipe wipe_params(params);
    ScopeWipe wipe_body(body);
    ScopeWipe wipe_type(contenttype);

    auto data =
        XorStr("type=webhook") +
        XorStr("&webid=") + curl_escape(nullptr, id) +
        XorStr("&params=") + curl_escape(nullptr, params) +
        XorStr("&body=") + curl_escape(nullptr, body) +
        XorStr("&conttype=") + curl_escape(nullptr, contenttype) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            load_response_data(json);
            return !json[(XorStr("response"))].is_null() ? json[(XorStr("response"))] : XorStr("");
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}

std::string KeyAuth::api::fetchonline() 
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();

    auto data =
        XorStr("type=fetchOnline") +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);

    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {
        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {
            std::string onlineusers;

            int y = atoi(api::app_data.numOnlineUsers.c_str());
            for (int i = 0; i < y; i++)
            {
                onlineusers.append(json[XorStr("users")][i][XorStr("credential")]); onlineusers.append(XorStr("\n"));
            }

            return onlineusers;
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}

void KeyAuth::api::fetchstats()
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();

    auto data =
        XorStr("type=fetchStats") +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);

    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);
    std::hash<int> hasher;
    int expectedHash = hasher(42);
    int result = VerifyPayload(signature, signatureTimestamp, response);
    if ((hasher(result ^ 0xA5A5) & 0xFFFF) == (expectedHash & 0xFFFF))
    {

        auto json = response_decoder.parse(response);
        if (json[(XorStr("ownerid"))] != get_ownerid()) {
            KA_EXIT(8);
        }

        std::string message = json[(XorStr("message"))];

        std::hash<int> hasher;
        size_t expectedHash = hasher(68);
        size_t resultCode = hasher(json[(XorStr("code"))]);

        if (!json[(XorStr("success"))] || (json[(XorStr("success"))] && (resultCode == expectedHash))) {

            load_response_data(json);

            if (json[(XorStr("success"))])
                load_app_data(json[(XorStr("appinfo"))]);
        }
        else {
            KA_EXIT(9);
        }
    }
    else {
        KA_EXIT(7);
    }
}

void KeyAuth::api::forgot(std::string username, std::string email)
{
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();
    ScopeWipe wipe_user(username);
    ScopeWipe wipe_email(email);

    auto data =
        XorStr("type=forgot") +
        XorStr("&username=") + curl_escape(nullptr, username) +
        XorStr("&email=") + curl_escape(nullptr, email) +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);
    auto json = response_decoder.parse(response);
    load_response_data(json);
}

void KeyAuth::api::logout() {
    std::lock_guard<std::recursive_mutex> api_lock(api_mutex_);
    checkInit();

    auto data =
        XorStr("type=logout") +
        XorStr("&sessionid=") + curl_escape(nullptr, sessionid) +
        XorStr("&name=") + curl_escape(nullptr, get_name()) +
        XorStr("&ownerid=") + curl_escape(nullptr, get_ownerid());
    ScopeWipe wipe_request_data(data);
    auto response = req(data, get_url());
    ScopeWipe wipe_response_body(response);
    auto json = response_decoder.parse(response);
    if (json[(XorStr("success"))]) {

        //clear all old user data from program
        user_data.createdate.clear();
        user_data.ip.clear();
        user_data.hwid.clear();
        user_data.lastlogin.clear();
        user_data.username.clear();
        user_data.subscriptions.clear();

        //clear sessionid
        secure_zero(sessionid);

        //clear enckey
        secure_zero(enckey);
        reset_auth_runtime();
        initialized = false;
        secure_zero(initialized_context_);
    }

    load_response_data(json);
}

void KeyAuth::api::start_ban_monitor(int interval_seconds, bool check_session, std::function<void()> on_ban)
{
    if (ban_monitor_running_.load()) return;
    if (ban_monitor_thread_.joinable()) {
        if (ban_monitor_thread_.get_id() == std::this_thread::get_id()) return;
        ban_monitor_thread_.join();
    }
    interval_seconds = (std::max)(1, interval_seconds);
    ban_monitor_detected_ = false;
    ban_monitor_running_ = true;
    ban_monitor_thread_ = std::thread([this, interval_seconds, check_session, on_ban]() {
        while (ban_monitor_running_.load()) {
            bool blacklisted = false;
            try {
                std::lock_guard<std::recursive_mutex> lock(api_mutex_);
                if (check_session) check(false);
                blacklisted = checkblack();
            } catch (const std::exception& e) {
                std::lock_guard<std::recursive_mutex> lock(api_mutex_);
                response.success = false;
                response.message = e.what();
            }
            if (blacklisted) {
                ban_monitor_detected_ = true;
                ban_monitor_running_ = false;
                if (on_ban) on_ban();
                return;
            }
            std::unique_lock<std::mutex> wait_lock(heartbeat_mutex_);
            heartbeat_cv_.wait_for(wait_lock, std::chrono::seconds(interval_seconds),
                [this] { return !ban_monitor_running_.load(); });
        }
    });
}

void KeyAuth::api::stop_ban_monitor()
{
    {
        std::lock_guard<std::mutex> lock(heartbeat_mutex_);
        ban_monitor_running_ = false;
    }
    heartbeat_cv_.notify_all();
    if (ban_monitor_thread_.joinable() &&
        ban_monitor_thread_.get_id() != std::this_thread::get_id()) {
        ban_monitor_thread_.join();
    }
}

bool KeyAuth::api::ban_monitor_running() const
{
    return ban_monitor_running_.load();
}

bool KeyAuth::api::ban_monitor_detected() const
{
    return ban_monitor_detected_.load();
}

std::string KeyAuth::api::expiry_remaining(const std::string& expiry)
{
    if (expiry.empty())
        return "unknown";
    long long exp = 0;
    try {
        exp = std::stoll(expiry);
    }
    catch (...) {
        return "unknown";
    }
    const long long now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    long long diff = exp - now;
    if (diff <= 0)
        return "expired";

    const long long days = diff / 86400;
    const long long weeks = days / 7;
    const long long months = days / 30;
    const long long hours = (diff % 86400) / 3600;
    const long long minutes = (diff % 3600) / 60;

    std::time_t tt = static_cast<std::time_t>(exp);
    std::tm tm{};
#ifdef _WIN32
    localtime_s(&tm, &tt);
#else
    tm = *std::localtime(&tt);
#endif
    char buf[32] = {};
    std::strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm);

    std::ostringstream out;
    out << days << "d " << hours << "h " << minutes << "m remaining"
        << " (expires " << buf << ", ~" << weeks << "w / " << months << "mo)";
    return out.str();
}

void KeyAuth::api::init_fail_delay()
{
    Sleep(kInitFailSleepMs);
}

void KeyAuth::api::bad_input_delay()
{
    Sleep(kBadInputSleepMs);
}

void KeyAuth::api::close_delay()
{
    Sleep(kCloseSleepMs);
}

bool KeyAuth::api::lockout_active(const lockout_state& state)
{
    return std::chrono::steady_clock::now() < state.locked_until;
}

int KeyAuth::api::lockout_remaining_ms(const lockout_state& state)
{
    if (!lockout_active(state))
        return 0;
    const auto now = std::chrono::steady_clock::now();
    const auto remaining = std::chrono::duration_cast<std::chrono::milliseconds>(state.locked_until - now).count();
    return remaining > 0 ? static_cast<int>(remaining) : 0;
}

void KeyAuth::api::record_login_fail(lockout_state& state, int max_attempts, int lock_seconds)
{
    if (max_attempts < 1)
        max_attempts = 1;
    if (lock_seconds < 1)
        lock_seconds = 1;
    state.fails += 1;
    if (state.fails >= max_attempts) {
        state.fails = 0;
        state.locked_until = std::chrono::steady_clock::now() + std::chrono::seconds(lock_seconds);
    }
}

void KeyAuth::api::reset_lockout(lockout_state& state)
{
    state.fails = 0;
    state.locked_until = std::chrono::steady_clock::time_point{};
}

int VerifyPayload(const std::string& signature, const std::string& timestamp, const std::string& body, long long received_at)
{
    integrity_check();
    const auto now = std::chrono::duration_cast<std::chrono::seconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    const auto result = keyauth_detail::verify_payload(signature, timestamp, body,
                                                       get_public_key_hex(), received_at > 0 ? received_at : now);
    if (result == keyauth_detail::PayloadResult::timestamp_skew) {
        throw KeyAuth::request_error("Signed response timestamp is outside the 120 second window. Synchronize the system clock and retry.");
    }
    if (result != keyauth_detail::PayloadResult::valid) {
        throw KeyAuth::request_error("KeyAuth response signature verification failed (reason " +
            std::to_string(static_cast<int>(result)) + "). Response rejected.");
    }
    return (42 ^ 0xA5A5) & 0xFFFF;
}

// credits https://stackoverflow.com/a/43002794
std::string get_str_between_two_str(const std::string& s,
    const std::string& start_delim,
    const std::string& stop_delim)
{
    const auto first_delim_pos = s.find(start_delim);
    if (first_delim_pos == std::string::npos)
        return {};
    const auto end_pos_of_first_delim = first_delim_pos + start_delim.length();
    if (stop_delim.empty()) return s.substr(end_pos_of_first_delim);
    const auto last_delim_pos = s.find(stop_delim, end_pos_of_first_delim);
    if (last_delim_pos == std::string::npos || last_delim_pos < end_pos_of_first_delim)
        return {};

    return s.substr(end_pos_of_first_delim,
        last_delim_pos - end_pos_of_first_delim);
}

std::string curl_escape(CURL* curl, const std::string& input)
{
    if (input.empty()) return {};
    if (input.size() > INT_MAX) throw KeyAuth::request_error("API field is too large.");
    char* encoded = curl_easy_escape(curl, input.data(), static_cast<int>(input.size()));
    if (!encoded) throw KeyAuth::request_error("Could not encode API field.");
    const auto release_encoded = [](char* value) noexcept {
        if (value) {
            SecureZeroMemory(value, std::strlen(value));
            curl_free(value);
        }
    };
    std::unique_ptr<char, decltype(release_encoded)> owner(encoded, release_encoded);
    return std::string(encoded);
}

std::string extract_host(const std::string& url)
{
    return keyauth_detail::parse_api_endpoint(url).host;
}

static bool is_ip_literal(const std::string& host)
{
    sockaddr_in sa4{};
    sockaddr_in6 sa6{};
    return inet_pton(AF_INET, host.c_str(), &sa4.sin_addr) == 1 ||
        inet_pton(AF_INET6, host.c_str(), &sa6.sin6_addr) == 1;
}

static bool is_private_or_loopback_ipv4(uint32_t address)
{
    return keyauth_detail::private_ipv4(address);
}

static bool is_loopback_ipv6(const in6_addr& address)
{
    return IN6_IS_ADDR_LOOPBACK(&address) != 0;
}

static bool is_private_or_loopback_ipv6(const in6_addr& address)
{
    return keyauth_detail::private_ipv6(address);
}

static bool ip_string_private_or_loopback(const std::string& address)
{
    return keyauth_detail::private_address(address);
}

static bool host_is_keyauth(const std::string& host_lower)
{
    if (host_lower == "keyauth.win" || host_lower == "keyauth.cc" || host_lower == "api-worker.keyauth.win")
        return true;
    const std::string suffix = ".keyauth.win";
    if (host_lower.size() > suffix.size() &&
        host_lower.compare(host_lower.size() - suffix.size(), suffix.size(), suffix) == 0)
        return true;
    return false;
}

static bool is_https_url(const std::string& url)
{
    const std::string prefix = "https://";
    if (url.size() < prefix.size())
        return false;
    for (size_t i = 0; i < prefix.size(); ++i) {
        const char c = keyauth_detail::ascii_lower(static_cast<unsigned char>(url[i]));
        if (c != prefix[i])
            return false;
    }
    return true;
}

static bool host_resolves_private_only(const std::string& host, bool& has_public)
{
    has_public = false;
    addrinfo hints{};
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_family = AF_UNSPEC;
    addrinfo* res = nullptr;
    if (getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0)
        return false;
    bool any = false;
    bool all_private = true;
    for (addrinfo* p = res; p; p = p->ai_next) {
        if (!p->ai_addr)
            continue;
        any = true;
        if (p->ai_family == AF_INET) {
            const auto* sa = reinterpret_cast<sockaddr_in*>(p->ai_addr);
            if (!is_private_or_loopback_ipv4(sa->sin_addr.s_addr)) {
                all_private = false;
                has_public = true;
            }
        } else if (p->ai_family == AF_INET6) {
            const auto* sa = reinterpret_cast<sockaddr_in6*>(p->ai_addr);
            if (!is_loopback_ipv6(sa->sin6_addr)) {
                all_private = false;
                has_public = true;
            }
        }
    }
    freeaddrinfo(res);
    if (!any)
        return false;
    return all_private;
}

static void collect_ips_from_dns(PDNS_RECORD rec, std::vector<std::string>& out)
{
    for (auto p = rec; p; p = p->pNext) {
        if (p->wType == DNS_TYPE_A) {
            char buf[INET_ADDRSTRLEN] = {};
            inet_ntop(AF_INET, &p->Data.A.IpAddress, buf, sizeof(buf));
            out.emplace_back(buf);
        } else if (p->wType == DNS_TYPE_AAAA) {
            char buf[INET6_ADDRSTRLEN] = {};
            inet_ntop(AF_INET6, &p->Data.AAAA.Ip6Address, buf, sizeof(buf));
            out.emplace_back(buf);
        }
    }
}

static bool dns_cache_poisoned(const std::string& host)
{
    if (host.empty())
        return false;

    std::vector<std::string> cached;
    std::vector<std::string> fresh;

    PDNS_RECORD rec_cached = nullptr;
    PDNS_RECORD rec_fresh = nullptr;

    if (DnsQuery_A(host.c_str(), DNS_TYPE_A, DNS_QUERY_STANDARD, nullptr, &rec_cached, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_cached, cached);
        DnsRecordListFree(rec_cached, DnsFreeRecordList);
    }
    if (DnsQuery_A(host.c_str(), DNS_TYPE_AAAA, DNS_QUERY_STANDARD, nullptr, &rec_cached, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_cached, cached);
        DnsRecordListFree(rec_cached, DnsFreeRecordList);
    }

    if (DnsQuery_A(host.c_str(), DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, nullptr, &rec_fresh, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_fresh, fresh);
        DnsRecordListFree(rec_fresh, DnsFreeRecordList);
    }
    if (DnsQuery_A(host.c_str(), DNS_TYPE_AAAA, DNS_QUERY_BYPASS_CACHE, nullptr, &rec_fresh, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_fresh, fresh);
        DnsRecordListFree(rec_fresh, DnsFreeRecordList);
    }

    if (cached.empty() || fresh.empty())
        return false;

    std::sort(cached.begin(), cached.end());
    cached.erase(std::unique(cached.begin(), cached.end()), cached.end());
    std::sort(fresh.begin(), fresh.end());
    fresh.erase(std::unique(fresh.begin(), fresh.end()), fresh.end());

    return cached != fresh;
}

static bool dns_fresh_contains_ip(const std::string& host, const std::string& ip)
{
    if (host.empty() || ip.empty())
        return false;
    std::vector<std::string> fresh;
    PDNS_RECORD rec_fresh = nullptr;
    if (DnsQuery_A(host.c_str(), DNS_TYPE_A, DNS_QUERY_BYPASS_CACHE, nullptr, &rec_fresh, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_fresh, fresh);
        DnsRecordListFree(rec_fresh, DnsFreeRecordList);
    }
    if (DnsQuery_A(host.c_str(), DNS_TYPE_AAAA, DNS_QUERY_BYPASS_CACHE, nullptr, &rec_fresh, nullptr) == ERROR_SUCCESS) {
        collect_ips_from_dns(rec_fresh, fresh);
        DnsRecordListFree(rec_fresh, DnsFreeRecordList);
    }
    if (fresh.empty())
        return false;
    for (const auto& entry : fresh) {
        if (_stricmp(entry.c_str(), ip.c_str()) == 0)
            return true;
    }
    return false;
}

bool hosts_override_present(const std::string& host)
{
    if (host.empty()) throw KeyAuth::request_error("Cannot inspect an empty API hostname.");
    std::wstring directory(32768, L'\0');
    const auto length = GetSystemWindowsDirectoryW(directory.data(), static_cast<UINT>(directory.size()));
    if (!length || length >= directory.size())
        throw KeyAuth::request_error("Cannot locate the Windows hosts file.");
    directory.resize(length);
    const auto path = std::filesystem::path(directory) / L"System32" / L"drivers" / L"etc" / L"hosts";
    HANDLE raw = CreateFileW(path.c_str(), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE, nullptr, OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL, nullptr);
    if (raw == INVALID_HANDLE_VALUE) {
        const auto code = GetLastError();
        if (code == ERROR_FILE_NOT_FOUND || code == ERROR_PATH_NOT_FOUND) return false;
        throw KeyAuth::request_error("Cannot read the Windows hosts file.");
    }
    struct FileOwner {
        HANDLE handle;
        ~FileOwner() { CloseHandle(handle); }
    } owner{raw};
    std::string pending;
    std::array<char, 4096> buffer{};
    DWORD count = 0;
    while (true) {
        if (!ReadFile(raw, buffer.data(), static_cast<DWORD>(buffer.size()), &count, nullptr))
            throw KeyAuth::request_error("Cannot read the Windows hosts file.");
        if (!count) break;
        pending.append(buffer.data(), count);
        size_t newline = 0;
        while ((newline = pending.find('\n')) != std::string::npos) {
            if (keyauth_detail::hosts_line_overrides(pending.substr(0, newline), host)) return true;
            pending.erase(0, newline + 1);
        }
        if (pending.size() > 65536) throw KeyAuth::request_error("Hosts file contains an oversized line.");
    }
    return keyauth_detail::hosts_line_overrides(pending, host);
}

struct RequestConnectionPolicy {
    CURL* curl = nullptr;
    std::string host;
    bool restrict_private = false;
    bool block_proxy = false;
    bool rejected = false;
};

static int validate_request_connection(void* userdata, char* ip, char*, int port, int) noexcept
{
    auto* policy = static_cast<RequestConnectionPolicy*>(userdata);
    try {
        long using_proxy = 0;
        if (!policy || !policy->curl || !ip ||
            curl_easy_getinfo(policy->curl, CURLINFO_USED_PROXY, &using_proxy) != CURLE_OK)
            return CURL_PREREQFUNC_ABORT;
        if (hosts_override_present(policy->host) ||
            !keyauth_detail::connection_address_allowed(ip, port, using_proxy != 0,
                policy->restrict_private, !policy->block_proxy)) {
            policy->rejected = true;
            return CURL_PREREQFUNC_ABORT;
        }
        return CURL_PREREQFUNC_OK;
    } catch (...) {
        if (policy) policy->rejected = true;
        return CURL_PREREQFUNC_ABORT;
    }
}

static std::wstring to_lower_ws(std::wstring value)
{
    std::transform(value.begin(), value.end(), value.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    return value;
}

static bool path_has_any(const std::wstring& p, const std::initializer_list<std::wstring>& needles)
{
    for (const auto& n : needles) {
        if (p.find(n) != std::wstring::npos)
            return true;
    }
    return false;
}

bool module_has_rwx_section(HMODULE mod)
{
    if (!mod)
        return false;
    auto base = reinterpret_cast<std::uintptr_t>(mod);
    auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE)
        return false;
    auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE)
        return false;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        const auto ch = section->Characteristics;
        if ((ch & IMAGE_SCN_MEM_EXECUTE) && (ch & IMAGE_SCN_MEM_WRITE))
            return true;
    }
    return false;
}

static bool verify_signature(const std::wstring& path)
{
    WINTRUST_FILE_INFO file_info{};
    file_info.cbStruct = sizeof(file_info);
    file_info.pcwszFilePath = path.c_str();

    WINTRUST_DATA trust_data{};
    trust_data.cbStruct = sizeof(trust_data);
    trust_data.dwUIChoice = WTD_UI_NONE;
    trust_data.fdwRevocationChecks = WTD_REVOKE_NONE;
    trust_data.dwUnionChoice = WTD_CHOICE_FILE;
    trust_data.pFile = &file_info;
    trust_data.dwStateAction = WTD_STATEACTION_IGNORE;

    GUID policy = WINTRUST_ACTION_GENERIC_VERIFY_V2;
    LONG status = WinVerifyTrust(nullptr, &policy, &trust_data);
    return status == ERROR_SUCCESS;
}

bool core_modules_signed()
{
    // verify core dll signatures and reject rwx sections -nigel
    const wchar_t* kModules[] = { L"ntdll.dll", L"kernel32.dll", L"kernelbase.dll", L"user32.dll" };
    for (const auto* name : kModules) {
        HMODULE mod = GetModuleHandleW(name);
        if (!mod)
            return false;
        wchar_t path[MAX_PATH] = {};
        if (!GetModuleFileNameW(mod, path, MAX_PATH))
            return false;
        if (!verify_signature(path))
            return false;
        if (module_has_rwx_section(mod))
            return false;
    }
    return true;
}

static bool reg_key_exists(HKEY root, const wchar_t* path)
{
    HKEY h = nullptr;
    const LONG res = RegOpenKeyExW(root, path, 0, KEY_READ, &h);
    if (res == ERROR_SUCCESS) {
        RegCloseKey(h);
        return true;
    }
    return false;
}

static bool file_exists(const std::wstring& path)
{
    const DWORD attr = GetFileAttributesW(path.c_str());
    return (attr != INVALID_FILE_ATTRIBUTES) && !(attr & FILE_ATTRIBUTE_DIRECTORY);
}

static std::wstring get_system_dir()
{
    wchar_t buf[MAX_PATH] = {};
    if (GetSystemDirectoryW(buf, MAX_PATH) == 0)
        return L"";
    return std::wstring(buf);
}

static std::wstring get_syswow_dir()
{
    wchar_t buf[MAX_PATH] = {};
    if (GetSystemWow64DirectoryW(buf, MAX_PATH) == 0)
        return L"";
    return std::wstring(buf);
}

static std::wstring normalize_path(std::wstring p)
{
    std::transform(p.begin(), p.end(), p.begin(),
        [](wchar_t c) { return static_cast<wchar_t>(towlower(c)); });
    while (!p.empty() && (p.back() == L'\\' || p.back() == L'/')) {
        p.pop_back();
    }
    return p;
}

static bool get_module_path(HMODULE mod, std::wstring& out)
{
    wchar_t path[MAX_PATH] = {};
    if (!mod)
        return false;
    if (!GetModuleFileNameW(mod, path, MAX_PATH))
        return false;
    out.assign(path);
    return true;
}

static bool module_in_system32(HMODULE mod)
{
    std::wstring mod_path;
    if (!get_module_path(mod, mod_path))
        return false;
    mod_path = normalize_path(mod_path);

    std::wstring sys = normalize_path(get_system_dir());
    if (sys.empty())
        return false;

    return mod_path.rfind(sys + L"\\", 0) == 0;
}

static uint32_t file_crc32(const std::wstring& path)
{
    std::ifstream f(path, std::ios::binary);
    if (!f.good()) return 0;
    std::vector<uint8_t> buf((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    if (buf.empty()) return 0;

    uint32_t crc = 0xFFFFFFFFu;
    for (uint8_t b : buf) {
        crc ^= b;
        for (int k = 0; k < 8; ++k) {
            uint32_t mask = (crc & 1u) ? 0xFFFFFFFFu : 0u;
            crc = (crc >> 1) ^ (0xEDB88320u & mask);
        }
    }
    return ~crc;
}

static bool critical_modules_safe()
{
    const wchar_t* system_mods[] = { L"wintrust.dll", L"crypt32.dll", L"bcrypt.dll" };
    for (const auto* name : system_mods) {
        HMODULE mod = GetModuleHandleW(name);
        if (!mod) return false;
        if (!module_in_system32(mod)) return false;
    }

    const wchar_t* app_mods[] = { L"libcurl.dll", L"libsodium.dll" };
    for (const auto* name : app_mods) {
        HMODULE mod = GetModuleHandleW(name);
        if (!mod) continue;
        std::wstring path;
        if (!get_module_path(mod, path)) return false;
        std::wstring p = normalize_path(path);

        if (p.find(L"\\appdata\\") != std::wstring::npos ||
            p.find(L"\\temp\\") != std::wstring::npos ||
            p.find(L"\\downloads\\") != std::wstring::npos) {
            return false;
        }
    }
    return true;
}

bool timing_anomaly_detected()
{
    const auto wall_now = std::chrono::system_clock::now();
    const auto steady_now = std::chrono::steady_clock::now();
    static auto wall_last = wall_now;
    static auto steady_last = steady_now;
    static ULONGLONG tick_last = GetTickCount64();
    static long long wall_last_sec = std::chrono::duration_cast<std::chrono::seconds>(
        wall_now.time_since_epoch()).count();
    const auto wall_delta = std::chrono::duration_cast<std::chrono::seconds>(wall_now - wall_last).count();
    const auto steady_delta = std::chrono::duration_cast<std::chrono::seconds>(steady_now - steady_last).count();
    wall_last = wall_now;
    steady_last = steady_now;
    const ULONGLONG tick_now = GetTickCount64();
    const long long tick_delta = static_cast<long long>((tick_now - tick_last) / 1000ULL);
    tick_last = tick_now;
    const long long wall_now_sec = std::chrono::duration_cast<std::chrono::seconds>(
        wall_now.time_since_epoch()).count();
    const long long wall_tick_delta = wall_now_sec - wall_last_sec;
    wall_last_sec = wall_now_sec;
    if (wall_delta < -60 || wall_delta > 300)
        return true;
    if (std::llabs(wall_delta - steady_delta) > 120)
        return true;
    if (std::llabs(wall_tick_delta - tick_delta) > 120)
        return true;
    return false;
}

static bool get_text_section_info(std::uintptr_t& base, size_t& size)
{
    const auto hmodule = GetModuleHandle(nullptr);
    if (!hmodule) return false;
    const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
    const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".text", 5) == 0) {
            base = base_0 + section->VirtualAddress;
            size = section->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static uint32_t rolling_crc32(const uint8_t* data, size_t len, size_t window, size_t stride)
{
    if (!data || len < window)
        return 0;
    uint32_t crc = 0xFFFFFFFFu;
    for (size_t i = 0; i + window <= len; i += stride) {
        for (size_t j = 0; j < window; ++j) {
            uint8_t b = data[i + j];
            crc ^= b;
            for (int k = 0; k < 8; ++k) {
                uint32_t mask = (crc & 1u) ? 0xFFFFFFFFu : 0u;
                crc = (crc >> 1) ^ (0xEDB88320u & mask);
            }
        }
    }
    return ~crc;
}

static bool get_data_section_info(std::uintptr_t& base, size_t& size)
{
    const auto hmodule = GetModuleHandle(nullptr);
    if (!hmodule) return false;
    const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
    const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".data", 5) == 0) {
            base = base_0 + section->VirtualAddress;
            size = section->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static bool get_rdata_section_info(std::uintptr_t& base, size_t& size)
{
    const auto hmodule = GetModuleHandle(nullptr);
    if (!hmodule) return false;
    const auto base_0 = reinterpret_cast<std::uintptr_t>(hmodule);
    const auto dos = reinterpret_cast<IMAGE_DOS_HEADER*>(base_0);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    const auto nt = reinterpret_cast<IMAGE_NT_HEADERS*>(base_0 + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return false;
    auto section = IMAGE_FIRST_SECTION(nt);
    for (auto i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++section) {
        if (std::memcmp(section->Name, ".rdata", 6) == 0) {
            base = base_0 + section->VirtualAddress;
            size = section->Misc.VirtualSize;
            return true;
        }
    }
    return false;
}

static uint32_t fnv1a(const uint8_t* data, size_t len)
{
    uint32_t hash = 2166136261u;
    for (size_t i = 0; i < len; ++i) {
        hash ^= data[i];
        hash *= 16777619u;
    }
    return hash;
}

void snapshot_text_hashes()
{
    if (text_hashes_ready.load())
        return;
    std::uintptr_t base = 0;
    size_t size = 0;
    if (!get_text_section_info(base, size) || size < 256)
        return;
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<size_t> dist(0, size - 64);
    text_hashes.clear();
    for (int i = 0; i < 8; ++i) {
        const size_t offset = dist(gen);
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(base + offset);
        text_hashes.push_back({ offset, 64, fnv1a(ptr, 64) });
    }
    text_hashes_ready.store(true);
}

bool text_hashes_ok()
{
    if (!text_hashes_ready.load())
        return true;
    std::uintptr_t base = 0;
    size_t size = 0;
    if (!get_text_section_info(base, size))
        return true;
    for (const auto& h : text_hashes) {
        if (h.offset + h.len > size)
            return false;
        const uint8_t* ptr = reinterpret_cast<const uint8_t*>(base + h.offset);
        if (fnv1a(ptr, h.len) != h.hash)
            return false;
    }
    return true;
}

void snapshot_text_page_protections()
{
    if (text_prot_ready.load())
        return;
    std::uintptr_t base = 0;
    size_t size = 0;
    if (!get_text_section_info(base, size))
        return;
    text_protections.clear();
    const size_t page = 0x1000;
    for (size_t off = 0; off < size; off += page) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(base + off), &mbi, sizeof(mbi)) == 0)
            continue;
        text_protections.emplace_back(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), mbi.Protect);
    }
    text_prot_ready.store(true);
}

void snapshot_data_page_protections()
{
    if (data_prot_ready.load())
        return;
    data_protections.clear();
    const size_t page = 0x1000;

    std::uintptr_t base = 0;
    size_t size = 0;
    if (get_data_section_info(base, size)) {
        for (size_t off = 0; off < size; off += page) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(base + off), &mbi, sizeof(mbi)) == 0)
                continue;
            data_protections.emplace_back(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), mbi.Protect);
        }
    }

    base = 0;
    size = 0;
    if (get_rdata_section_info(base, size)) {
        for (size_t off = 0; off < size; off += page) {
            MEMORY_BASIC_INFORMATION mbi{};
            if (VirtualQuery(reinterpret_cast<const void*>(base + off), &mbi, sizeof(mbi)) == 0)
                continue;
            data_protections.emplace_back(reinterpret_cast<std::uintptr_t>(mbi.BaseAddress), mbi.Protect);
        }
    }

    data_prot_ready.store(true);
}

bool text_page_protections_ok()
{
    if (!text_prot_ready.load())
        return true;
    for (const auto& entry : text_protections) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(entry.first), &mbi, sizeof(mbi)) == 0)
            return false;
        const DWORD prot = mbi.Protect;
        if (prot != entry.second)
            return false;
        const bool exec = (prot & PAGE_EXECUTE) || (prot & PAGE_EXECUTE_READ) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_EXECUTE_WRITECOPY);
        const bool write = (prot & PAGE_READWRITE) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_WRITECOPY) || (prot & PAGE_EXECUTE_WRITECOPY);
        if (!exec || write)
            return false;
    }
    return true;
}

bool data_page_protections_ok()
{
    if (!data_prot_ready.load())
        return true;
    for (const auto& entry : data_protections) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (VirtualQuery(reinterpret_cast<const void*>(entry.first), &mbi, sizeof(mbi)) == 0)
            return false;
        const DWORD prot = mbi.Protect;
        if (prot != entry.second)
            return false;
        const bool exec = (prot & PAGE_EXECUTE) || (prot & PAGE_EXECUTE_READ) || (prot & PAGE_EXECUTE_READWRITE) || (prot & PAGE_EXECUTE_WRITECOPY);
        if (exec)
            return false;
    }
    return true;
}


KeyAuth::api::~api()
{
    stop_ban_monitor();
    {
        std::lock_guard<std::mutex> lock(heartbeat_mutex_);
        heartbeat_stop_ = true;
    }
    heartbeat_cv_.notify_all();
    if (heartbeat_thread_.joinable()) heartbeat_thread_.join();
    secure_zero(sessionid);
    secure_zero(enckey);
    secure_zero(magic_link_email_);
    secure_zero(initialized_context_);
    secure_zero(name_enc_);
    secure_zero(ownerid_enc_);
    secure_zero(version_enc_);
    secure_zero(url_enc_);
    secure_zero(path_enc_);
    reset_auth_runtime();
}

void KeyAuth::api::start_heartbeat()
{
    if (heartbeat_thread_.joinable()) return;
    heartbeat_thread_ = std::thread([this]() {
        std::unique_lock<std::mutex> wait_lock(heartbeat_mutex_);
        while (!heartbeat_cv_.wait_for(wait_lock, std::chrono::seconds(60),
                                      [this] { return heartbeat_stop_; })) {
            wait_lock.unlock();
            {
                std::lock_guard<std::recursive_mutex> lock(api_mutex_);
                if (LoggedIn.load()) {
                    try {
                        check(false);
                    } catch (const std::exception& e) {
                        response.success = false;
                        response.message = e.what();
                    }
                }
            }
            wait_lock.lock();
        }
    });
}

void KeyAuth::api::setDebug(bool value) {
    KeyAuth::api::debug = value;
}

std::string KeyAuth::api::req(std::string data, const std::string& url) {
    ScopeWipe request_wipe(data);
    response.success = false;
    signature.clear();
    signatureTimestamp.clear();
    // gate requests on integrity checks to reduce bypasses -nigel
    integrity_check();
    // usage: keep this in req() so every api call is protected -nigel
    if (LoggedIn.load() && !request_bypasses_local_auth(data) && !local_auth_valid(false)) {
        if (!local_auth_valid(false, false)) {
            reset_auth_runtime();
            throw request_error(XorStr("local auth gate failed."));
        }
        check();
        if (!response.success || !local_auth_valid(false))
            throw request_error("Session validation failed before the requested operation.");
        response.success = false;
        signature.clear();
        signatureTimestamp.clear();
    }
    keyauth_detail::ApiEndpoint endpoint;
    try {
        endpoint = keyauth_detail::parse_api_endpoint(url);
    } catch (const std::exception& e) {
        throw request_error(e.what());
    }
    const std::string host = endpoint.host;
    const std::string operation = data.substr(0, data.find('&')).substr(5);
    if (!initialization_context_valid())
        throw request_error("Application configuration changed after initialization. Create a new API instance.");
    const auto configured = keyauth_detail::parse_api_endpoint(get_url());
    if (!keyauth_detail::request_endpoint_matches(configured.url, endpoint.url, operation))
        throw request_error("Request endpoint does not match the configured application.");
    const std::string requested_owner = get_ownerid();
    const std::string requested_name = get_name();
    std::string requested_session = sessionid;
    ScopeWipe wipe_requested_session(requested_session);
    if (hosts_override_present(host))
        throw request_error("Windows hosts file overrides the configured API hostname.");
    if (!allowed_hosts.empty() && std::none_of(allowed_hosts.begin(), allowed_hosts.end(),
        [&](const std::string& entry) { return keyauth_detail::hostname_matches(host, entry); }))
        throw request_error("API hostname is not allowed.");

    CURL* curl = curl_easy_init();
    if (!curl) {
        throw request_error(XorStr("CURL Initialization Failed!"));
    }

    std::unique_ptr<CURL, decltype(&curl_easy_cleanup)> curl_guard(curl, curl_easy_cleanup);
    const bool is_file_request = operation == "file";
    const bool query_request = is_file_request || keyauth_detail::email_request_uses_get(operation);
    keyauth_detail::ResponseBuffer response_buffer{{}, is_file_request ? max_download_response_bytes : max_api_response_bytes};
    auto& to_return = response_buffer.body;
    ScopeWipe wipe_response_buffer(to_return);
    SignatureHeaders sig_headers;
    std::string request_url = endpoint.url;
    ScopeWipe url_wipe(request_url);
    if (query_request) {
        request_url += (request_url.find('?') == std::string::npos) ? "?" : "&";
        request_url += data;
    }

    RequestConnectionPolicy connection_policy{curl, host, block_private_dns || host_is_keyauth(host), block_proxy, false};
    if (curl_easy_setopt(curl, CURLOPT_PREREQFUNCTION, validate_request_connection) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_PREREQDATA, &connection_policy) != CURLE_OK)
        throw request_error("The linked libcurl does not support connection validation.");

    if (curl_easy_setopt(curl, CURLOPT_URL, request_url.c_str()) != CURLE_OK)
        throw request_error("Could not apply the required API transport policy.");
    if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L) != CURLE_OK)
        throw request_error("Could not apply the required API transport policy.");
    if (curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L) != CURLE_OK)
        throw request_error("Could not apply the required API transport policy.");
    if (curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 0L) != CURLE_OK)
        throw request_error("Could not apply the required API transport policy.");
    if (curl_easy_setopt(curl, CURLOPT_MAXREDIRS, 0L) != CURLE_OK)
        throw request_error("Could not apply the required API transport policy.");
    if (curl_easy_setopt(curl, CURLOPT_PROTOCOLS, CURLPROTO_HTTPS) != CURLE_OK)
        throw request_error("Could not apply the required API transport policy.");
    if (curl_easy_setopt(curl, CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS) != CURLE_OK)
        throw request_error("Could not apply the required API transport policy.");
    if (curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 60L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, is_file_request ? 0L : 120L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_TCP_KEEPALIVE, 1L) != CURLE_OK)
        throw request_error("Could not apply the required API connection settings.");
    curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
    curl_easy_setopt(curl, CURLOPT_ACCEPT_ENCODING, "");
#if LIBCURL_VERSION_NUM >= 0x072200
    if (curl_easy_setopt(curl, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_2) != CURLE_OK)
        throw request_error("Could not apply the required API transport policy.");
#endif
    if (query_request) {
        curl_easy_setopt(curl, CURLOPT_HTTPGET, 1L);
    } else {
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, data.c_str());
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, static_cast<long>(data.size()));
    }
    curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_WRITEDATA, &response_buffer);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &sig_headers);
    curl_easy_setopt(curl, CURLOPT_USERAGENT, "KeyAuth");

    if ((require_pinning || block_custom_ca) && pinned_public_keys.empty()) {
        curl_guard.reset();
        throw request_error("Public key pinning is required but no pins are configured.");
    }
    if (!pinned_public_keys.empty()) {
#if LIBCURL_VERSION_NUM >= 0x072700
        std::string pins;
        for (const auto& pin : pinned_public_keys) {
            if (pin.empty() || pin.find_first_of("\r\n") != std::string::npos || pin.find('\0') != std::string::npos)
                throw request_error("Configured public key pin is empty or invalid.");
            if (pinned_public_keys.size() > 1 && pin.rfind("sha256//", 0) != 0)
                throw request_error("Multiple pins require SHA-256 public key hashes.");
            if (!pins.empty()) pins += ';';
            pins += pin;
        }
        if (curl_easy_setopt(curl, CURLOPT_PINNEDPUBLICKEY, pins.c_str()) != CURLE_OK) {
            curl_guard.reset();
            throw request_error("Public key pinning is unsupported by the active TLS backend.");
        }
#else
        throw request_error(XorStr("Pinned public key not supported by this libcurl build."));
#endif
    }

    long http_status = 0;
    // Perform once: a missing signature must not replay a state-changing request.
    for (int attempt = 0; attempt < 1; ++attempt) {
        sig_headers.signature.clear();
        sig_headers.timestamp.clear();
        to_return.clear();

        CURLcode code = curl_easy_perform(curl);
        if (response_buffer.exceeded) throw request_error("API response exceeds the configured size limit.");
        if (code != CURLE_OK) {
            std::string errorMsg = connection_policy.rejected
                ? "API connection rejected by hostname or address policy."
                : "CURL Error: " + std::string(curl_easy_strerror(code));
            curl_guard.reset();
            throw request_error(errorMsg);
        }

        if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status) != CURLE_OK ||
            (http_status < 200 || http_status >= 300) && http_status != 400 && http_status != 401 && http_status != 403) {
            curl_guard.reset();
            throw request_error("KeyAuth HTTP error " + std::to_string(http_status) +
                  ". Check service availability or network/proxy configuration.");
        }
        if (sig_headers.conflicting) {
            curl_guard.reset();
            throw request_error("Conflicting signature headers in API response.");
        }

        long ssl_verify = 0;
        if (curl_easy_getinfo(curl, CURLINFO_SSL_VERIFYRESULT, &ssl_verify) == CURLE_OK) {
            if (ssl_verify != 0) {
                curl_guard.reset();
                throw request_error(XorStr("SSL verify result failed."));
            }
        }

        if ((!is_file_request || require_signed_downloads || http_status >= 400) && (sig_headers.signature.empty() || sig_headers.timestamp.empty())) {
            curl_guard.reset();
            throw request_error(XorStr("Successful HTTP response is missing KeyAuth signature headers. Check API endpoint or intermediary; response rejected."));
        }

        break;
    }

    std::string sig_hex;
    const bool sig_norm_ok = normalize_signature_header(sig_headers.signature, sig_hex);
    if (!sig_norm_ok && (!is_file_request || require_signed_downloads || http_status >= 400 || !sig_headers.signature.empty() || !sig_headers.timestamp.empty())) {
        curl_guard.reset();
        throw request_error(XorStr("invalid signature header format."));
    }

    std::string ts = sig_headers.timestamp;
    trim_ws(ts);
    strip_quotes(ts);
    const bool ts_ok = (ts.size() >= 10 && ts.size() <= 13 &&
        std::all_of(ts.begin(), ts.end(), [](unsigned char c) { return c >= '0' && c <= '9'; }));
    if (!ts_ok && (!is_file_request || require_signed_downloads || http_status >= 400 || !sig_headers.signature.empty() || !sig_headers.timestamp.empty())) {
        curl_guard.reset();
        throw request_error(XorStr("invalid signature timestamp header format."));
    }

    const bool sig_ok = sig_norm_ok && ts_ok;

    // Enforce cryptographic payload verification on every request path.
    if (sig_ok) {
        int verify_result;
        try {
            verify_result = VerifyPayload(sig_hex, ts, to_return, is_file_request ? sig_headers.timestamp_received_at : 0);
        } catch (...) {
            curl_guard.reset();
            throw;
        }
        if ((verify_result & 0xFFFF) != ((42 ^ 0xA5A5) & 0xFFFF)) {
            curl_guard.reset();
            throw request_error(XorStr("payload verification marker mismatch."));
        }
    }

    if (sodium_init() < 0) {
        curl_guard.reset();
        throw request_error(XorStr("libsodium init failed in request guard."));
    }

    unsigned char sig_guard[64] = { 0 };
    unsigned char pk_guard[32] = { 0 };
    if (sig_ok) {
        if (sodium_hex2bin(sig_guard, sizeof(sig_guard), sig_hex.c_str(), sig_hex.size(), nullptr, nullptr, nullptr) != 0) {
            curl_guard.reset();
            throw request_error(XorStr("signature decode failed in request guard."));
        }
        const std::string pubkey_hex_guard = get_public_key_hex();
        if (sodium_hex2bin(pk_guard, sizeof(pk_guard), pubkey_hex_guard.c_str(), pubkey_hex_guard.size(), nullptr, nullptr, nullptr) != 0) {
            curl_guard.reset();
            throw request_error(XorStr("public key decode failed in request guard."));
        }
        std::string signed_message_guard = ts + to_return;
        ScopeWipe wipe_signed_message(signed_message_guard);
        if (crypto_sign_ed25519_verify_detached(sig_guard,
            reinterpret_cast<const unsigned char*>(signed_message_guard.data()),
            signed_message_guard.size(),
            pk_guard) != 0) {
            curl_guard.reset();
            throw request_error(XorStr("signature verify failed in request guard."));
        }
    }

    if (sig_ok) {
        const auto envelope = nlohmann::json::parse(to_return, nullptr, false);
        try {
            keyauth_detail::validate_response_context(envelope, requested_owner, requested_name, requested_session, operation);
        } catch (const std::exception& e) {
            throw request_error(e.what());
        }
        if (http_status >= 400 && (!envelope.is_object() || !envelope.contains("success") ||
            !envelope["success"].is_boolean() || envelope["success"].get<bool>()))
            throw request_error("Invalid signed API error response.");
    }

    char* effective_url = nullptr;
    if (curl_easy_getinfo(curl, CURLINFO_EFFECTIVE_URL, &effective_url) == CURLE_OK && effective_url) {
        if (!is_https_url(effective_url)) {
            curl_guard.reset();
            throw request_error(XorStr("effective url not https."));
        }
        std::string eff_host = extract_host(effective_url);
        std::string host_lower = host;
        std::string eff_lower = eff_host;
        std::transform(host_lower.begin(), host_lower.end(), host_lower.begin(),
            [](unsigned char c) { return keyauth_detail::ascii_lower(c); });
        std::transform(eff_lower.begin(), eff_lower.end(), eff_lower.begin(),
            [](unsigned char c) { return keyauth_detail::ascii_lower(c); });
        if (!eff_lower.empty() && eff_lower != host_lower) {
            curl_guard.reset();
            throw request_error(XorStr("effective url host mismatch."));
        }
    }

    if (KeyAuth::api::debug) {
        debugInfo("n/a", "n/a", R"({"response_body":"omitted"})", "n/a");
    }
    // no maximum or minimum response size check. -nigel
    curl_guard.reset();
    secure_zero(data);
    signature = sig_hex;
    signatureTimestamp = ts;
    return std::move(to_return);
}

[[noreturn]] void error(std::string message) {
    throw KeyAuth::request_error(message);
}
std::string checksum()
{
    std::wstring path(32768, L'\0');
    const DWORD length = GetModuleFileNameW(nullptr, path.data(), static_cast<DWORD>(path.size()));
    if (!length || length >= path.size()) throw KeyAuth::request_error("Cannot locate executable for API checksum.");
    path.resize(length);
    return keyauth_detail::file_md5(std::filesystem::path(path));
}

std::string getPath() {
    const wchar_t* program_data = _wgetenv(L"ALLUSERSPROFILE");
    if (program_data && *program_data) {
        return wide_to_utf8(program_data);
    }
    return std::filesystem::current_path().u8string();
}

void RedactField(nlohmann::json& jsonObject, const std::string& fieldName)
{

    if (jsonObject.contains(fieldName)) {
        jsonObject[fieldName] = "REDACTED";
    }
}

void KeyAuth::api::debugInfo(std::string data, std::string url, std::string response, std::string headers) {
    // output debug logs to C:\ProgramData\KeyAuth\Debug\

    if (!KeyAuth::api::debug) {
        return;
    }

    std::string redacted_response = "n/a";
    // for logging the headers, since response is not avaliable there
    if (response != "n/a") {
        //turn response into json
        nlohmann::json responses = nlohmann::json::parse(response);
        RedactField(responses, "sessionid");
        RedactField(responses, "ownerid");
        RedactField(responses, "app");
        RedactField(responses, "name");
        RedactField(responses, "contents");
        RedactField(responses, "key");
        RedactField(responses, "username");
        RedactField(responses, "password");
        RedactField(responses, "version");
        RedactField(responses, "fileid");
        RedactField(responses, "webhooks");
        redacted_response = responses.dump();
    }

    std::string redacted_data = "n/a";
    // for logging the headers, since request JSON is not avaliable there
    if (data != "n/a") {
        //turn data into json
        std::replace(data.begin(), data.end(), '&', ' ');

        nlohmann::json datas;

        std::istringstream iss(data);
        std::vector<std::string> results((std::istream_iterator<std::string>(iss)),
            std::istream_iterator<std::string>());

        for (auto const& value : results) {
            const auto pos = value.find('=');
            if (pos == std::string::npos)
                continue;
            datas[value.substr(0, pos)] = value.substr(pos + 1);
        }

        RedactField(datas, "sessionid");
        RedactField(datas, "ownerid");
        RedactField(datas, "app");
        RedactField(datas, "name");
        RedactField(datas, "key");
        RedactField(datas, "username");
        RedactField(datas, "password");
        RedactField(datas, "contents");
        RedactField(datas, "version");
        RedactField(datas, "fileid");
        RedactField(datas, "webhooks");

        redacted_data = datas.dump();
    }

    // Keep debug paths in UTF-16; narrowing Unicode filenames loses characters. -nigel
    std::wstring executable_path(32768, L'\0');
    const DWORD path_length = GetModuleFileNameW(nullptr, executable_path.data(),
        static_cast<DWORD>(executable_path.size()));
    if (!path_length || path_length >= executable_path.size()) {
        throw request_error("Cannot locate executable for debug log.");
    }
    executable_path.resize(path_length);

    const auto executable_name = std::filesystem::path(executable_path).filename().stem();
    const auto log_path = keyauth_detail::native_file_path(getPath()) / L"KeyAuth" / L"Debug" / executable_name;
    std::filesystem::create_directories(log_path);

    if (response.length() >= 500) { return; }

    //fetch todays time
    std::time_t t = std::time(nullptr);
    char time[80];

    std::tm* localTime = std::localtime(&t);

    std::strftime(time, sizeof(time), "%m-%d-%Y", localTime);

    std::ofstream logfile(log_path / (std::string(time) + ".txt"), std::ios::app);

    //get time
    int hours = localTime->tm_hour;
    int minutes = localTime->tm_min;

    std::string period;
    if (hours < 12) {
        period = "AM";
    }
    else {
        period = "PM";
        hours -= 12;
    }

    std::string formattedMinutes = (minutes < 10) ? "0" + std::to_string(minutes) : std::to_string(minutes);

    std::string currentTimeString = std::to_string(hours) + ":" + formattedMinutes + " " + period;

    std::string contents = "\n\n@ " + currentTimeString + "\nURL: " + url + "\nData sent : " + redacted_data + "\nResponse : " + redacted_response + "\n" + headers;

    logfile << contents;

    logfile.close();
}

static bool compare_text_to_disk()
{
    wchar_t filename[MAX_PATH] = {};
    DWORD size = MAX_PATH;
    if (!QueryFullProcessImageName(GetCurrentProcess(), 0, filename, &size))
        return false;

    HANDLE file = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
    if (file == INVALID_HANDLE_VALUE)
        return false;

    HANDLE map = CreateFileMappingW(file, 0, PAGE_READONLY, 0, 0, 0);
    if (!map) {
        CloseHandle(file);
        return false;
    }

    void* mapped = MapViewOfFile(map, FILE_MAP_READ, 0, 0, 0);
    if (!mapped) {
        CloseHandle(map);
        CloseHandle(file);
        return false;
    }

    auto base_mem = reinterpret_cast<std::uintptr_t>(GetModuleHandle(nullptr));
    auto base_disk = reinterpret_cast<std::uintptr_t>(mapped);

    auto dos_mem = reinterpret_cast<IMAGE_DOS_HEADER*>(base_mem);
    auto dos_disk = reinterpret_cast<IMAGE_DOS_HEADER*>(base_disk);

    if (dos_mem->e_magic != IMAGE_DOS_SIGNATURE || dos_disk->e_magic != IMAGE_DOS_SIGNATURE) {
        UnmapViewOfFile(mapped);
        CloseHandle(map);
        CloseHandle(file);
        return false;
    }

    auto nt_mem = reinterpret_cast<IMAGE_NT_HEADERS*>(base_mem + dos_mem->e_lfanew);
    auto nt_disk = reinterpret_cast<IMAGE_NT_HEADERS*>(base_disk + dos_disk->e_lfanew);

    auto sec_mem = IMAGE_FIRST_SECTION(nt_mem);
    auto sec_disk = IMAGE_FIRST_SECTION(nt_disk);

    for (unsigned i = 0; i < nt_mem->FileHeader.NumberOfSections; ++i, ++sec_mem, ++sec_disk) {
        if (std::memcmp(sec_mem->Name, ".text", 5) == 0) {
            const size_t size_text = sec_mem->Misc.VirtualSize;
            const uint8_t* mem_ptr = reinterpret_cast<const uint8_t*>(base_mem + sec_mem->VirtualAddress);
            const uint8_t* disk_ptr = reinterpret_cast<const uint8_t*>(base_disk + sec_disk->PointerToRawData);
            bool same = (std::memcmp(mem_ptr, disk_ptr, size_text) == 0);

            UnmapViewOfFile(mapped);
            CloseHandle(map);
            CloseHandle(file);
            return same;
        }
    }

    UnmapViewOfFile(mapped);
    CloseHandle(map);
    CloseHandle(file);
    return false;
}

void KeyAuth::api::checkInit() {
    if (!initialized) {
        error(XorStr("You need to run KeyAuthApp.init() before other API functions."));
    }
    if (!initialization_context_valid())
        throw request_error("Application configuration changed after initialization. Create a new API instance.");
}

void integrity_check() {
    // PE bytes and page permissions change legitimately under the Windows loader,
    // instrumentation and OS hotpatching. Authentication uses signed API replies.
    (void)get_public_key_hex();
}

// Clean up seed data (file and registry key)
void cleanUpSeedData(const std::string& seed) {

    // Clean up the seed file
    std::string file_path = "C:\\ProgramData\\" + seed;
    if (std::filesystem::exists(file_path)) {
        std::filesystem::remove(file_path);
    }

    // Clean up the seed registry entry
    std::string regPath = "Software\\" + seed;
    RegDeleteKeyA(HKEY_CURRENT_USER, regPath.c_str()); 
}
