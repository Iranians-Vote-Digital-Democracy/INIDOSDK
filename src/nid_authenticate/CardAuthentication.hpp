#pragma once

#include <cstdint>
#include <string>
#include <stdexcept>
#include <iostream>
#include <vector>

template<int sizeInBytes >
struct CommandParameterStr {
    char str[sizeInBytes];
    int size;
    CommandParameterStr(const char* myStr) {
        strncpy(str, myStr, sizeInBytes);
        size = strlen(myStr);
    }
};

template<int count >
struct CommandParameterInt64 {
    int64_t arr[count];
    int size;
    CommandParameterInt64(int64_t* arr_a, int size_a) {
        memcpy(arr, arr_a, size_a * sizeof(int64_t));
        size = size_a;
    }
    CommandParameterInt64() {
        size = 0;
    }
};

// If you want the NO-CRLF variant (like 0x40000001):
#ifndef CRYPT_STRING_BASE64_NOCRLF
#define CRYPT_STRING_BASE64_NOCRLF 0x40000001
#endif


// Function pointer type definitions
typedef int64_t(__fastcall* PFN_GET_NEW_INSTANCE)(int64_t* handle, int64_t param);
typedef int64_t(__fastcall* PFN_FREE_INSTANCE)(int64_t* handle, int64_t instance);
typedef int32_t(__fastcall* PFN_SET_PARAMETER)(int64_t* handle, int64_t instance, int64_t paramId, void* value);
typedef int32_t(__fastcall* PFN_GET_PARAMETER)(int64_t* handle, int64_t instance, int64_t paramId, void* value);
typedef int32_t(__fastcall* PFN_EXECUTE)(int64_t* handle, int64_t instance);
typedef int64_t(__fastcall* PFN_FREE_LIBRARY)(int64_t* handle);
typedef int64_t* (__fastcall* PFN_LOAD_LIBRARY)();

// -------------------------------------------------------------
// Extern function pointers (from your main.cpp):
// -------------------------------------------------------------
extern int64_t(__fastcall* pfn_get_new_instance)(int64_t* handle, int64_t paramId);
extern int64_t(__fastcall* pfn_free_instance)(int64_t* handle, int64_t instance);
extern int32_t(__fastcall* pfn_set_parameter)(int64_t* handle, int64_t instance, int64_t paramId, void* value);
extern int32_t(__fastcall* pfn_execute)(int64_t* handle, int64_t instance);
extern PFN_GET_PARAMETER pfn_get_parameter;

// -------------------------------------------------------------
// Extern error helper (from your main.cpp):
// -------------------------------------------------------------
extern std::string dk_getCommandError(int errorCode);

// -------------------------------------------------------------
// Extern global variables you rely on
// (In your code, you have them in main.cpp or elsewhere.):
// -------------------------------------------------------------
extern bool dk_ShowFingerPrintUI;
extern bool dk_ShowFaceInputUI;
extern int  dk_AuthenticationMethod;
extern int  dk_FingerIndex1;
extern int  dk_FingerIndex2;
extern int  dk_fingerStatus1;
extern int  dk_fingerStatus2;

// If you have more (like dk_SpSignatureServerAddress, etc.), you can extern them here.
// For example:
//   extern std::string dk_SpSignatureServerAddress;
//   extern std::string dk_setSpSignature_spId;

// -------------------------------------------------------------
// The CardAuthentication class
// -------------------------------------------------------------
class CardAuthentication
{
public:
    int64_t m_authV1Instance = 0;
public:
    CardAuthentication() = default;
    ~CardAuthentication() = default;

    /**
     * Top-level method: does “CardAuthenticate” logic
     */
    bool CardAuthenticate(int64_t rcx0, char* libraryPtr);

private:
    // 1) Creates “Authenticate_v1” => paramID=630,
    //    sets LoA, credentials, scope, spSignature, etc.
    int64_t setParametersCardAuthenticate(char* libraryPtr);

    // 2) Replaces the old “dk_checkAuthentication(...)”
    int64_t checkAuthentication(char* libraryPtr);

    // 3) Replaces the old “dk_SetFaceDataCredentials(...)”
    //    We skip actual face/fingerprint data, but create paramID=350
    int64_t setFaceDataCredentials(char* libraryPtr);

    void setCredentialsFingerPrint(
        char* libraryPtr,
        int64_t credentialsInstance,
        int authFingerIndex,
        int64_t& outFinger1,
        int64_t& outFinger2);

    int64_t setFingerPrintData(char* libraryPtr, int fingerIndex);

    int64_t setFaceData(char* /*libraryPtr*/);

    // 4) Replaces the old “dk_setRequiredInfo(...)”
    int64_t setRequiredInfo(char* libraryPtr);

    // 4a) Replaces “dk_SetRequiredCitizenInfo(...)”
    int64_t setRequiredCitizenInfo(char* libraryPtr, int infoType, char isMandatory);

    // 4b) Replaces “dk_setSupplementInfo(...)”
    int64_t setSupplementInfo(char* libraryPtr, int infoType);


    /**
 * Encodes raw bytes [data, data+dataSize) in Base64 via CryptBinaryToStringW,
 * then returns a UTF-8 std::string containing that base64 text.
 *
 * @param data     Pointer to raw bytes
 * @param dataSize Number of bytes
 * @return         UTF-8 base64 text
 */
    std::string dk_ToBase64String(const uint8_t* data, size_t dataSize);

    // ------------------------------------------------------------------------
    // Utility for setting parameters with error-check
    // ------------------------------------------------------------------------
    template<typename T>
    void setParameterOrThrow(char* libraryPtr, int64_t instance, int64_t paramId,
        const T& value, const char* errorContext)
    {
        int err = pfn_set_parameter((int64_t*)libraryPtr, instance, paramId, (void*)&value);
        if (err != 0)
        {
            std::string msg = std::string(errorContext) + "| error: " + dk_getCommandError(err);
            throw std::runtime_error(msg);
        }
    }

    template<typename T>
    void setParameterOrThrowNoPointer(char* libraryPtr, int64_t instance, int64_t paramId,
        const T& value, const char* errorContext)
    {
        int err = pfn_set_parameter((int64_t*)libraryPtr, instance, paramId, (void*)value); // <-- no pointer madness here
        if (err != 0)
        {
            std::string msg = std::string(errorContext) + "| error: " + dk_getCommandError(err);
            throw std::runtime_error(msg);
        }
    }

    // Utility for free_instance (if instance != 0)
    void freeInstanceIfValid(char* libraryPtr, int64_t instance)
    {
        if (instance)
        {
            pfn_free_instance((int64_t*)libraryPtr, instance);
        }
    }
};
