#pragma once

#include <cstdint>
#include <string>
#include <stdexcept>
#include <vector>

/**
 * External function pointers and helper from your project.
 */
extern int64_t(__fastcall* pfn_get_new_instance)(int64_t* handle, int64_t paramId);
extern int64_t(__fastcall* pfn_free_instance)(int64_t* handle, int64_t instance);
extern int32_t(__fastcall* pfn_set_parameter)(int64_t* handle, int64_t instance, int64_t paramId, void* value);
extern int32_t(__fastcall* pfn_execute)(int64_t* handle, int64_t instance);
extern int32_t(__fastcall* pfn_get_parameter)(int64_t* handle, int64_t instance, int64_t paramId, void* value);
extern std::string dk_getCommandError(int errorCode);


/**
 * SpSignatureManager class that encapsulates logic
 * from the previous setSpSignature(...) implementation.
 */
class SpSignatureManager
{
public:
    /**
     * Creates and returns a new SpSignature instance (paramId=80),
     * sets the relevant fields, and frees the subordinate "signature data" instance.
     */
    int64_t createSpSignature(char* libraryPtr);

private:
    /**
     * Generates a nonce (64-bit random).
     */
    uint64_t generateNonce();

    /**
     * Formats current time in a minimal ISO8601-like format.
     */
    std::string formatIso8601();

    /**
     * Encodes raw bytes into Base64 text.
     */
    std::string dk_ToBase64String(const uint8_t* data, size_t dataSize);

    /**
     * Creates a new instance (paramId=50) for signature data,
     * fetches or builds the signature, stores it in param=58, etc.
     */
    int64_t setSpSignatureData(char* libraryPtr, const std::string& inputData = "");

    /**
     * Frees an instance if valid.
     */
    void freeInstanceIfValid(char* libraryPtr, int64_t instance);

    /**
     * Helper for setting parameters (scalar).
     */
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

    /**
     * Helper for setting parameters (instance handle).
     */
    template<typename T>
    void setParameterOrThrowNoPointer(char* libraryPtr, int64_t instance, int64_t paramId,
        const T& value, const char* errorContext)
    {
        int err = pfn_set_parameter((int64_t*)libraryPtr, instance, paramId, (void*)value);
        if (err != 0)
        {
            std::string msg = std::string(errorContext) + "| error: " + dk_getCommandError(err);
            throw std::runtime_error(msg);
        }
    }
};
