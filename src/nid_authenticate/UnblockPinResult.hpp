#pragma once

#include <cstdint>
#include <string>
#include <stdexcept>

// External function pointers and helpers.
extern int64_t(__fastcall* pfn_get_new_instance)(int64_t* handle, int64_t paramId);
extern int64_t(__fastcall* pfn_free_instance)(int64_t* handle, int64_t instance);
extern int32_t(__fastcall* pfn_get_parameter)(int64_t* handle, int64_t instance, int64_t paramId, void* value);
extern std::string dk_getCommandError(int errorCode);

/**
 * UnblockPinResult
 */
class UnblockPinResult
{
public:
    /**
     * Retrieves the UnblockPin result in JSON.
     *  - Creates paramID=670 => "UnblockPinResult"
     *  - paramID=704 => "UnblockPin_v1_UnblockPinResult"
     *  - Reads param=671 => "UnblockPinResult_ResultType"
     *  - If EXCEPTION => gather exception
     *  - If SUCCESS => gather success
     */
    std::string getUnblockPinResult(char* libraryPtr, int64_t unblockPinV1Instance);

private:
    /**
     * Gathers the integer resultType => paramID=671 => __int64 in IDA
     */
    int getResultType(char* libraryPtr, int64_t unblockPinResultInstance);

    /**
     * If resultType=1 => read paramID=672 => "UnblockPinResult_ResultException"
     * paramID=32..35 => strings or int
     */
    std::string gatherExceptionJson(char* libraryPtr, int64_t unblockPinResultInstance);

    /**
     * If resultType=0 => read paramID=673..678 => strings or int64
     * paramID=679 => signature => gatherSignatureJson
     */
    std::string gatherSuccessJson(char* libraryPtr, int64_t unblockPinResultInstance);

    /**
     * paramID=50 => signature => paramID=52..58,55 => strings or int if needed
     */
    std::string gatherSignatureJson(char* libraryPtr, int64_t signatureInstance);

    /**
     * Helper: free instance if valid
     */
    void freeInstanceIfValid(char* libraryPtr, int64_t instance);

    /**
     * We read a string if the code has a char buffer in IDA
     */
    std::string readParamAsString(char* libraryPtr, int64_t instance, int64_t paramId, size_t bufferSize);

    uint64_t readParamAsUInt64(char* libraryPtr, int64_t instance, int64_t paramId);
};
