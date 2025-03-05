#pragma once

#include <string>
#include <stdexcept>
#include <vector>
#include "CardAuthentication.hpp"

/**
 * Provides methods to gather "personal info" JSON from IDA-reversed code:
 *   1) getPersonalInfoJson(...) replicates dk_GetPersonalInfo_1
 *   2) getPersonalInfo0(...) replicates dk_GetPersonalInfo_0
 *   3) createJsonFromLoa(...) replicates dk_CreateJsonFromLoa
 */
class CardAuthPersonalInfo
{
public:
    CardAuthPersonalInfo() = default;
    ~CardAuthPersonalInfo() = default;

    /**
     * Replicates dk_GetPersonalInfo_1 logic:
     *   - Creates new instance paramId=480 => "LoA"
     *   - Then sets paramId=102 => LoA
     *   - Builds the LoA JSON
     *   - Then enumerates paramId=103 => "Assertion_ResponseInfo"
     *   - For each, we could call getPersonalInfo0(...) to build JSON
     *   - Returns final JSON: { "loa": {...}, "responseInfos":[ ... ] }
     */
    std::string getPersonalInfoJson(char* libraryPtr, int64_t mdasHandle, int64_t assertionObj);

private:
    /**
     * Replicates dk_CreateJsonFromLoa:
     *   param=482 => AuthenticationMethod
     *   param=483 => revocationCheck
     *   param=484 => authorizationCheck
     *   param=485 => faceMatchingSeverity
     */
    std::string createJsonFromLoa(char* libraryPtr, int64_t loaInstance);

    /**
     * Replicates dk_GetAuthenticationMethodString switch-case:
     *   0 => "PIN", 1 => "PIN_PIN", 2 => "PIN_FP", 3 => "PIN_FP_FP",
     *   4 => "PIN_FACE", 5 => "PIN_PIN_FACE", 6 => "PIN_FP_FACE", 7 => "PIN_FP_FP_FACE"
     */
    std::string getAuthenticationMethodString(int authMethod);

    /**
     * Replicates dk_GetPersonalInfo_0 logic:
     *   - Reads param=302 => InfoType
     *   - Reads param=304 => Source
     *   - Reads param=303 => Value
     *   - Then constructs JSON:
     *       { "infoType":"...", "value":"...", "source":"..." }
     *   Possibly handles base64 decoding, hex, etc.
     *
     *   We keep the IDA snippet's references to "create_json_form_response_info|get_parameter|ResponseInfo_*".
     */
    std::string getPersonalInfo0(char* libraryPtr, int64_t responseInfoInstance);

    /**
     * Helper to read param as string or integer.
     */
    std::string getParamAsString(char* libraryPtr, int64_t instance, int64_t paramId, bool isString);

    /**
     * Frees the instance if valid.
     */
    void freeInstanceIfValid(char* libraryPtr, int64_t instance);
};
