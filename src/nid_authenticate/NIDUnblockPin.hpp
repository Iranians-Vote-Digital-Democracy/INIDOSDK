#pragma once

#include <cstdint>
#include <string>
#include <stdexcept>
#include <iostream>

// These should already be declared elsewhere in your project:
extern int64_t(__fastcall* pfn_get_new_instance)(int64_t* handle, int64_t paramId);
extern int64_t(__fastcall* pfn_free_instance)(int64_t* handle, int64_t instance);
extern int32_t(__fastcall* pfn_set_parameter)(int64_t* handle, int64_t instance, int64_t paramId, void* value);
extern int32_t(__fastcall* pfn_execute)(int64_t* handle, int64_t instance);
extern int32_t(__fastcall* pfn_get_parameter)(int64_t* handle, int64_t instance, int64_t paramId, void* value);

extern std::string dk_getCommandError(int errorCode);

/**
 * NIDUnblockPin class
 */
class NIDUnblockPin
{
public:
    /**
     * Creates the “UnblockPin_v1” instance (paramID=700), sets the parameters:
     *  - param=701 => UnblockPin_v1_PinType
     *  - param=702 => UnblockPin_v1_Credentials
     *  - param=703 => UnblockPin_v1_SpSignature
     *
     * Returns the newly created instance handle or 0 if something failed.
     */
    int64_t getNIDUnblockInstance(char* libraryPtr);

    /**
     * High-level method replicating the behavior of “dk_NIDUnblockPIN_1”.
     *  - Creates and sets up an unblock instance
     *  - Executes the operation
     *  - Skips the result parsing for now (we do not implement dk_getUnblockPinResult here)
     *  - On success, returns true and places any string output into outResult
     *  - Throws std::runtime_error on error
     */
    std::string NIDUnblockPIN1(char* libraryPtr);

private:
    /**
     * Creates the “Credentials” instance for UnblockPin (paramID=350).
     */
    int64_t getUnblockPinCredentials(char* libraryPtr);

    /**
     * Helper for setting parameters (non-instance).
     */
    template<typename T>
    void setParameterOrThrow(char* libraryPtr, int64_t instance, int64_t paramId,
        const T& value, const char* errorContext)
    {
        int err = pfn_set_parameter((int64_t*)libraryPtr, instance, paramId, (void*)&value);
        if (err != 0)
        {
            std::string msg = std::string(errorContext) + " | error: " + dk_getCommandError(err);
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
            std::string msg = std::string(errorContext) + " | error: " + dk_getCommandError(err);
            throw std::runtime_error(msg);
        }
    }

    /**
     * Frees a previously allocated instance if valid.
     */
    void freeInstanceIfValid(char* libraryPtr, int64_t instance)
    {
        if (instance)
        {
            pfn_free_instance((int64_t*)libraryPtr, instance);
        }
    }
};
