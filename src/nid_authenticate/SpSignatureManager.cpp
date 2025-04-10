#include "SpSignatureManager.hpp"
#include <random>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <windows.h>
#include <winhttp.h>
#include "CardAuthentication.hpp"

// Suppose these are the global strings the reversed code references
// (like qword_1404BEE98, qword_1404BEEB8, etc.)
static const char* g_signatureAlgorithm = "1.2.840.113549.1.1.11";
static const char* g_hashAlgorithm = "2.16.840.1.101.3.4.2.1";
static const char* g_algorithmVersion = "1.00";

// (Optionally define or extern any spId or server address here.)
// For example:
//   std::string dk_SpSignatureServerAddress = "http://127.0.0.1/spSignature";
//   std::string dk_setSpSignature_spId      = "MyServiceProviderID";


// If you want the NO-CRLF variant (like 0x40000001):
#ifndef CRYPT_STRING_BASE64_NOCRLF
#define CRYPT_STRING_BASE64_NOCRLF 0x40000001
#endif

/**
 * Example stub for an HTTP call that retrieves signature bytes.
 */
static bool dk_GetSpSignatureValueHTTP(const std::string& serverUrl,
    std::vector<uint8_t>& outSignatureBytes)
{
    // Stub: Simulate server response.
    // In reality, you would perform WinHttpOpen, WinHttpConnect, etc.
    std::string fakeResponse = "HelloFromSignatureServer";
    outSignatureBytes.assign(fakeResponse.begin(), fakeResponse.end());
    return true;
}

/**
 * Creates the SpSignature instance with paramID=80, sets various parameters,
 * and returns the instance handle.
 */
int64_t SpSignatureManager::createSpSignature(char* libraryPtr)
{
    // 1) generate nonce => sub_1400B0FB0 => store into *a2
    printf("setSpSignature 1\n");
    uint64_t nonce = generateNonce();
    printf("setSpSignature 2\n");
    // 2) get iso8601 => "dk_format_ISO_8601"
    std::string isoTime = formatIso8601();
    printf("setSpSignature 3\n");
    // 3) do "dk_SetSpSignatureData" => returns sub-instance handle
    int64_t signDataHandle = setSpSignatureData(libraryPtr);
    if (!signDataHandle)
    {
        // if zero => no signature
        return 0;
    }

    // paramId=80 => "SpSignature" instance
    int64_t new_instance = pfn_get_new_instance((int64_t*)libraryPtr, 80LL);
    if (!new_instance)
    {
        freeInstanceIfValid(libraryPtr, signDataHandle);
        return 0;
    }


    // paramId=85 => signDataHandle
    setParameterOrThrowNoPointer(libraryPtr, new_instance, 85LL, signDataHandle,
        "set_sp_signature|set_parameter|SpSignature_Signature");

    // paramId=82 => spId => from some global or stub. For now we use a placeholder:
    {
        CommandParameterStr<10244> spId("MyServiceProviderID");
        setParameterOrThrow(libraryPtr, new_instance, 82LL, spId,
            "set_sp_signature|set_parameter|SpSignature_SpId");
    }

    // paramId=83 => Nonce => we pass (char*)a2 or a2 itself
    setParameterOrThrow(libraryPtr, new_instance, 83LL, nonce,
        "set_sp_signature|set_parameter|SpSignature_Nonce");

    // paramId=84 => Timestamp => isoTime
    {
        CommandParameterStr<10244> ts(isoTime.c_str());
        setParameterOrThrow(libraryPtr, new_instance, 84LL, ts,
            "set_sp_signature|set_parameter|SpSignature_Timestamp");
    }

    // free the signDataHandle
    freeInstanceIfValid(libraryPtr, signDataHandle);
    return new_instance;
}

/**
 * Generates a random 64-bit value as nonce.
 */
uint64_t SpSignatureManager::generateNonce()
{
    std::random_device rd;
    uint64_t val = ((uint64_t)rd() << 32) ^ rd();
    return val;
}

/**
 * Minimal date-time formatting.
 */
std::string SpSignatureManager::formatIso8601()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    auto tt = system_clock::to_time_t(now);
    std::tm tmBuf;
    gmtime_s(&tmBuf, &tt);

    std::ostringstream oss;
    oss << std::put_time(&tmBuf, "%d-%m-%YT%H:%M:%S") << 'z';
    return oss.str();
}

/**
 * Converts raw bytes to Base64 via CryptBinaryToStringW with CRYPT_STRING_BASE64_NOCRLF.
 */
std::string SpSignatureManager::dk_ToBase64String(const uint8_t* data, size_t dataSize)
{
    if (!data || dataSize == 0)
        return std::string();

    DWORD pcchString = 0;
    BOOL ok = CryptBinaryToStringW(
        data,
        static_cast<DWORD>(dataSize),
        CRYPT_STRING_BASE64_NOCRLF,
        nullptr,
        &pcchString
    );
    if (!ok || pcchString == 0)
        return std::string();

    std::wstring wideBase64;
    wideBase64.resize(pcchString);

    ok = CryptBinaryToStringW(
        data,
        static_cast<DWORD>(dataSize),
        CRYPT_STRING_BASE64_NOCRLF,
        &wideBase64[0],
        &pcchString
    );
    if (!ok)
        return std::string();

    if (!wideBase64.empty() && wideBase64.back() == L'\0')
        wideBase64.pop_back();

    int utf8Size = WideCharToMultiByte(
        CP_UTF8,
        0,
        wideBase64.c_str(),
        static_cast<int>(wideBase64.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (utf8Size <= 0)
        return std::string();

    std::string result;
    result.resize(utf8Size);

    WideCharToMultiByte(
        CP_UTF8,
        0,
        wideBase64.c_str(),
        static_cast<int>(wideBase64.size()),
        &result[0],
        utf8Size,
        nullptr,
        nullptr
    );

    return result;
}

/**
 * Creates the sub-instance (paramId=50) that holds signature data,
 * calls HTTP or other logic to retrieve raw bytes, converts to base64,
 * and sets param=52..54..58, etc.
 */
int64_t SpSignatureManager::setSpSignatureData(char* libraryPtr, const std::string& inputData)
{
    // 1) Create new_instance => paramId=50
    printf("setSpSignatureData called\n");
    int64_t new_instance = pfn_get_new_instance((int64_t*)libraryPtr, 50LL);
    if (!new_instance)
    {
        return 0; // fail
    }
    // 2) Possibly build or parse "inputData" if needed.
    //    The reversed snippet had "rdx0" plus "data=...&workerName=..."
    //    We'll skip the complex string manipulation and proceed to the HTTP step.

    // 3) HTTP => retrieve raw signature bytes
    std::vector<uint8_t> signatureBytes;
    bool httpOk = dk_GetSpSignatureValueHTTP(
        /*serverName=*/"127.0.0.1:8080",  // or your real server
        /*...*/
        signatureBytes
    );
    if (!httpOk || signatureBytes.empty())
    {
        // If HTTP fails, we skip => free new_instance => return 0
        freeInstanceIfValid(libraryPtr, new_instance);
        return 0;
    }

    // 4) Convert those bytes to base64
    std::string base64Signature = dk_ToBase64String(signatureBytes.data(), signatureBytes.size());

    // 5) Now set these param IDs on the new_instance:
    //    paramId=52 => "Signature_SignatureAlgorithm"
    //    paramId=53 => "Signature_HashAlgorithm"
    //    paramId=54 => "Signature_AlgorithmVersion"
    //    paramId=58 => "Signature_SignatureValue"

    // 5a) paramId=52 => signatureAlgorithm
    {
        CommandParameterStr<10244> alg(g_signatureAlgorithm);
        setParameterOrThrow(libraryPtr, new_instance, 52LL, alg,
            "set_signature|set_parameter|Signature_SignatureAlgorithm");
    }

    // 5b) paramId=53 => hashAlgorithm
    {
        CommandParameterStr<10244> hashAlg(g_hashAlgorithm);
        setParameterOrThrow(libraryPtr, new_instance, 53LL, hashAlg,
            "set_signature|set_parameter|Signature_HashAlgorithm");
    }

    // 5c) paramId=54 => algorithmVersion
    {
        CommandParameterStr<10244> ver(g_algorithmVersion);
        setParameterOrThrow(libraryPtr, new_instance, 54LL, ver,
            "set_signature|set_parameter|Signature_AlgorithmVersion");
    }

    // 5d) paramId=58 => base64 signature
    {
        CommandParameterStr<10244> b64(base64Signature.c_str());
        setParameterOrThrow(libraryPtr, new_instance, 58LL, b64,
            "set_signature|set_parameter|Signature_SignatureValue");
    }
    // 6) Return new_instance => success
    return new_instance;
}

/**
 * Frees the instance if it's non-zero.
 */
void SpSignatureManager::freeInstanceIfValid(char* libraryPtr, int64_t instance)
{
    if (instance)
    {
        pfn_free_instance((int64_t*)libraryPtr, instance);
    }
}
