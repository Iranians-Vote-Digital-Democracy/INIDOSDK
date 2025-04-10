#pragma once

#include <string>
#include <stdexcept>
#include <iostream>
#include <vector>
#include "CardAuthentication.hpp"
#include "CardAuthPersonalInfo.hpp"

/**
 * Provides functionality to retrieve and parse the card authentication result
 * after the "authenticate_service|execute|Authenticate_v1" call.
 */
class CardAuthResult
{
private:
    int m_authenticationResultType = 0;
public:
    CardAuthResult() = default;
    ~CardAuthResult() = default;

    /**
     * Retrieves the JSON-formatted card authentication result.
     * @param libraryPtr Pointer to the loaded MDAS library.
     * @param authServiceInstance The instance used by the authentication call.
     * @return JSON string with the card authentication result.
     */
    std::string getCardAuthenticationResult(char* libraryPtr, int64_t authServiceInstance);

private:
    /**
     * Creates instance paramId=120, then uses pfn_get_parameter(..., 636, instance).
     */
    int64_t getAuthenticationResultInstance(char* libraryPtr, int64_t authServiceInstance);

    /**
     * Checks if result type is EXCEPTION (1) or SUCCESS (anything else).
     * Reads paramId=129 => "AuthenticationResult_ResultType".
     */
    int getResultType(char* libraryPtr, int64_t resultInst);

    /**
     * If resultType == 1 => parse the "ResultException" => paramId=131
     * Build JSON like: {"resultType":"EXCEPTION","resultException":...}
     */
    std::string gatherExceptionJson(char* libraryPtr, int64_t authResultInstance);

    /**
     * If resultType != 1 => parse success fields and signature info, plus
     * "assertion" personal info, plus any "ResultException".
     */
    std::string gatherSuccessJson(char* libraryPtr, int64_t authResultInstance);

    /**
     * Builds the signature JSON from signature instance => paramId=50:
     * param=52 => signatureAlgorithm
     * param=53 => hashAlgorithm
     * param=54 => algorithmVersion
     * param=56 => CACertificate
     * param=57 => endCertificate
     * param=58 => signatureValue
     * param=55 => DomainParameters
     */
    std::string gatherSignatureJson(char* libraryPtr, int64_t signatureInstance);

    /**
     * Reads any "ResultException" => paramId=131 => new instance=30 => parse fields (32..35).
     */
    std::string gatherResultExceptionJson(char* libraryPtr, int64_t authResultInstance);

    /**
     * Reads parameter as string or integer => returns std::string.
     */
    std::string getParamAsString(char* libraryPtr, int64_t instance, int64_t paramId, bool isString);

    /**
     * Replicates the IDA logic for "create_json_form_result_exception" (param=32..35).
     * Inlined in gatherExceptionJson(...) and gatherResultExceptionJson(...).
     * We rely on "dk_getCommandError(...)" to throw if needed.
     */


     /**
  * Reads param as string (if isString=true) or as int => returns std::string.
  */
    template <int strSizeInBytes>
    std::string getParamAsString(char* libraryPtr, int64_t instance, int64_t paramId, bool isString)
    {
        if (isString)
        {
            CommandParameterStr<strSizeInBytes> temp("");
            int err = pfn_get_parameter((int64_t*)libraryPtr, instance, paramId, (void*)&temp);
            if (err != 0)
                return "";
            return std::string(temp.str, temp.size);
        }
        else
        {
            int64_t val = 0;
            int err = pfn_get_parameter((int64_t*)libraryPtr, instance, paramId, (void*)&val);
            if (err != 0)
                return "0";
            return std::to_string(val);
        }
    }

    uint64_t readParamAsUInt64(char* libraryPtr, int64_t instance, int64_t paramId)
    {
        uint64_t val = 0;
        int err = pfn_get_parameter((int64_t*)libraryPtr, instance, paramId, &val);
        if (err != 0)
        {
            // If it fails => default is 0
            return 0;
        }
        return val;
    }

     /**
      * Frees the instance if valid.
      */
    void freeInstanceIfValid(char* libraryPtr, int64_t instance);

    int64_t dk_checkAuthentication(char* libraryPtr);
    int64_t dk_getLevelOfAssuranceChecks(char* libraryPtr, int64_t a2, int64_t a3);
};
