#include "NIDUnblockPin.hpp"
#include "SpSignatureManager.hpp"
#include "UnblockPinResult.hpp"
#include <inttypes.h>

// Represents the PIN type for unblock (0 => ID_PIN, 1 => SIGN_PIN)
static int dk_unblockPinType = 1;
/**
 * Creates an instance with paramID=350 (credentials).
 * The disassembly shows a free_instance call on (0LL), which is typically no-op.
 */
int64_t NIDUnblockPin::getUnblockPinCredentials(char* libraryPtr)
{
    // paramID=350 => credentials
    int64_t newInstance = pfn_get_new_instance((int64_t*)libraryPtr, 350LL);
    // The original code snippet calls a free_instance on 0, but that is effectively a no-op.
    // pfn_free_instance((int64_t*)libraryPtr, 0); // this doesn't even make sense
    return newInstance;
}

/**
 * Replicates the logic from 'dk_GetNIDUnblockInstance'.
 * paramID=700 => "UnblockPin_v1"
 *   param=701 => UnblockPin_v1_PinType (an integer)
 *   param=702 => UnblockPin_v1_Credentials (an instance)
 *   param=703 => UnblockPin_v1_SpSignature (an instance)
 */
int64_t NIDUnblockPin::getNIDUnblockInstance(char* libraryPtr)
{
    // 1) Obtain the SpSignature instance

    SpSignatureManager spMgr;
    int64_t spSignatureInst = spMgr.createSpSignature(libraryPtr);
    printf("spSignatureInstance = %" PRId64 "\n", spSignatureInst);

    // 2) Obtain the UnblockPin credentials
    int64_t credentialsInst = getUnblockPinCredentials(libraryPtr);
    if (!credentialsInst)
    {
        // If credentials is 0 => error
        freeInstanceIfValid(libraryPtr, spSignatureInst);
        return 0;
    }

    // 3) Create the UnblockPin_v1 instance => paramID=700
    int64_t unblockInst = pfn_get_new_instance((int64_t*)libraryPtr, 700LL);
    if (!unblockInst)
    {
        freeInstanceIfValid(libraryPtr, spSignatureInst);
        freeInstanceIfValid(libraryPtr, credentialsInst);
        return 0;
    }

    // param=701 => UnblockPin_v1_PinType => int
    // Use setParameterOrThrow for non-instance data
    setParameterOrThrow(libraryPtr, unblockInst, 701LL, dk_unblockPinType,
        "set_unblock_pin_service_parameters|UnblockPin_v1_PinType");

    // param=702 => UnblockPin_v1_Credentials => instance handle
    setParameterOrThrowNoPointer(libraryPtr, unblockInst, 702LL, credentialsInst,
        "set_unblock_pin_service_parameters|UnblockPin_v1_Credentials");

    // param=703 => UnblockPin_v1_SpSignature => instance handle
    setParameterOrThrowNoPointer(libraryPtr, unblockInst, 703LL, spSignatureInst,
        "set_unblock_pin_service_parameters|UnblockPin_v1_SpSignature");

    // 4) Free the subordinate instances now that they've been assigned
    freeInstanceIfValid(libraryPtr, spSignatureInst);
    freeInstanceIfValid(libraryPtr, credentialsInst);

    return unblockInst;
}

/**
 * Replicates the logic from “dk_NIDUnblockPIN_1”.
 *  - Creates the unblock instance via getNIDUnblockInstance(...)
 *  - Executes the instance
 *  - Skips retrieving the final result (dk_getUnblockPinResult) for now
 *  - Places a dummy string or outcome in outResult
 */
std::string NIDUnblockPin::NIDUnblockPIN1(char* libraryPtr)
{
    // 1) Create the "UnblockPin_v1" instance
    int64_t unblockInst = getNIDUnblockInstance(libraryPtr);
    if (!unblockInst)
    {
        throw std::runtime_error("NIDUnblockPIN1|error: Failed to create UnblockPin instance");
    }

    printf("[+] About to execute Unblock PIN in MDAS\n");
    // 2) Execute => similar to mdas_client_execute(a3, v7) in the disassembly
    int err = pfn_execute((int64_t*)libraryPtr, unblockInst);
    if (err != 0)
    {
        // Retrieve the error text
        std::string msg = dk_getCommandError(err);
        freeInstanceIfValid(libraryPtr, unblockInst);
        throw std::runtime_error("unblock_pin_service|execute|UnblockPin_v1 | error: " + msg);
    }

    UnblockPinResult res;
    std::string jsonOut = res.getUnblockPinResult(libraryPtr, unblockInst);

    // 4) Free our main instance
    freeInstanceIfValid(libraryPtr, unblockInst);
    return jsonOut;
}
