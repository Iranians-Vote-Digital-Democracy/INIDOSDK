#include "CardAuthResult.hpp"
#include "CardAuthPersonalInfo.hpp"
#include <vector>
#include <cstring>
#include <cstdio>
#include <inttypes.h>

/**
 * Retrieves the final JSON-formatted authentication result,
 * reflecting the logic from "dk_GetCardAuthenticationResult".
 */
std::string CardAuthResult::getCardAuthenticationResult(char* libraryPtr, int64_t authServiceInstance)
{
    // 1) Create an instance for "AuthenticationResult" => paramId=120
    int64_t authResultInst = getAuthenticationResultInstance(libraryPtr, authServiceInstance);
    if (!authResultInst)
    {
        // IDA returns "211" on error => we can do {"error":211}
        return "{\"error\":211}";
    }

    // 2) Read resultType => paramId=129
    int resultType = getResultType(libraryPtr, authResultInst);
    m_authenticationResultType = resultType;
    // 3) If EXCEPTION => gather exception JSON, else gather success JSON
    if (resultType == 1)
    {
        std::string exJson = gatherExceptionJson(libraryPtr, authResultInst);
        freeInstanceIfValid(libraryPtr, authResultInst);
        return exJson;
    }
    else
    {
        std::string successJson = gatherSuccessJson(libraryPtr, authResultInst);
        freeInstanceIfValid(libraryPtr, authResultInst);
        return successJson;
    }
}

int64_t CardAuthResult::getAuthenticationResultInstance(char* libraryPtr, int64_t authServiceInstance)
{
    // "AuthenticationResult" => paramId=120
    int64_t authResultInst = pfn_get_new_instance((int64_t*)libraryPtr, 120LL);
    if (!authResultInst)
        return 0;

    // paramId=636 => "Authenticate_v1_AuthenticationResult"
    // We'll do a 'get_parameter'. If it fails, we free and return 0.
    int err = pfn_get_parameter((int64_t*)libraryPtr, authServiceInstance, 636LL, (void*)authResultInst);
    if (err != 0)
    {
        pfn_free_instance((int64_t*)libraryPtr, authResultInst);
        return 0;
    }
    return authResultInst;
}

int CardAuthResult::getResultType(char* libraryPtr, int64_t resultInst)
{
    // paramId=129 => "AuthenticationResult_ResultType"
    // If reading fails, we treat it as an exception.
    int resultType = 0;
    int err = pfn_get_parameter((int64_t*)libraryPtr, resultInst, 129LL, (void*)&resultType);
    if (err != 0) {
        printf("[-] CardAuthResult::getResultType failed | err = %d | resultType = %d \n", err, resultType);
    }
    return resultType;
}

/**
 * If resultType == 1 => gather "ResultException"
 * using paramId=131 => new instance=30 => parse paramId=32..35
 * from the IDA snippet "create_json_form_result_exception|get_parameter|ResultException_*"
 */
std::string CardAuthResult::gatherExceptionJson(char* libraryPtr, int64_t authResultInstance)
{
    // Create "ResultException" => paramId=30
    int64_t exceptionInst = pfn_get_new_instance((int64_t*)libraryPtr, 30LL);
    if (!exceptionInst)
        return "{\"resultType\":\"EXCEPTION\",\"resultException\":{}}";

    // paramId=131 => "AuthenticationResult_ResultException"
    //  IDA snippet:
    //    Block.capacity=15; Block.size=0; ...
    //    str_construct((void ***)&Block, "print_authentication_result|get_parameter|AuthenticationResult_ResultException", 0x4EuLL);
    int err = pfn_get_parameter((int64_t*)libraryPtr, authResultInstance, 131LL, (void*)exceptionInst);
    if (err != 0)
    {
        freeInstanceIfValid(libraryPtr, exceptionInst);
        return "{\"resultType\":\"EXCEPTION\",\"resultException\":{}}";
    }

    // The IDA code for the fields => paramId=32..35
    // In IDA: 
    //   str_construct((void ***)&Block, "create_json_form_result_exception|get_parameter|ResultException_Category", 0x48uLL);
    //   pfn_get_parameter(... param=32)
    //   ...
    // We'll replicate that with "setParameterOrThrow" or direct approach.

    // category => paramId=32
    CommandParameterStr<10256> catBuf("");
    err = pfn_get_parameter((int64_t*)libraryPtr, exceptionInst, 32LL, (void*)&catBuf);
    if (err) {
        printf("[-] Failed: create_json_form_result_exception|get_parameter|ResultException_Category\n");
    }
    std::string category = std::string(catBuf.str);

    // cause => paramId=33
    CommandParameterStr<10256> causeBuf("");
    err = pfn_get_parameter((int64_t*)libraryPtr, exceptionInst, 33LL, (void*)&causeBuf); 
    if (err) {
        printf("[-] Failed: create_json_form_result_exception|get_parameter|ResultException_Cause\n");
    }
    std::string cause = std::string(causeBuf.str);

    // field => paramId=34
    CommandParameterStr<10256> fieldBuf("");
    err = pfn_get_parameter((int64_t*)libraryPtr, exceptionInst, 34LL, (void*)&fieldBuf);
    if (err) {
        printf("[-] Failed: create_json_form_result_exception|get_parameter|ResultException_Field\n");
    }
    std::string field = std::string(fieldBuf.str);

    // retryCount => paramId=35
    int retryCountVal = 0;
    err = pfn_get_parameter((int64_t*)libraryPtr, exceptionInst, 35LL, (void*)&retryCountVal);
    if (err) {
        printf("[-] Failed: create_json_form_result_exception|get_parameter|ResultException_RetryCount\n");
    }

    freeInstanceIfValid(libraryPtr, exceptionInst);

    // Build final JSON
    //  {"resultType":"EXCEPTION","resultException":{"category":"...","cause":"...","field":"...","retryCount":N}}
    std::string exCore = "{";
    exCore += "\"category\":\"" + category + "\",";
    exCore += "\"cause\":\"" + cause + "\",";
    exCore += "\"field\":\"" + field + "\",";
    exCore += "\"retryCount\":" + std::to_string(retryCountVal);
    exCore += "}";

    std::string out = "{\"resultType\":\"EXCEPTION\",\"resultException\":" + exCore + "}";
    return out;
}

/**
 * If resultType != 1 => gather success fields from IDA snippet:
 * paramId=122 => Id
 * paramId=123 => MdasId
 * paramId=124 => Nonce (int)
 * paramId=125 => SpId
 * paramId=126 => MdasTimestamp
 * paramId=127 => SpTimestamp
 * paramId=128 => Signature => paramId=50
 * paramId=130 => Assertion => paramId=100 => personal info
 * plus optionally parse "ResultException" => paramId=131
 */
std::string CardAuthResult::gatherSuccessJson(char* libraryPtr, int64_t authResultInstance)
{

    std::string id = getParamAsString<10244>(libraryPtr, authResultInstance, 122LL, true);
    std::string mdasId = getParamAsString<10244>(libraryPtr, authResultInstance, 123LL, true);
    std::string nonce = getParamAsString<1>(libraryPtr, authResultInstance, 124LL, false);
    std::string spId = getParamAsString<10256>(libraryPtr, authResultInstance, 125LL, true);
    std::string mdasTime = getParamAsString<10244>(libraryPtr, authResultInstance, 126LL, true);
    std::string spTime = getParamAsString<10244>(libraryPtr, authResultInstance, 127LL, true);

    // paramId=128 => "AuthenticationResult_Signature"
    int64_t signatureInst = pfn_get_new_instance((int64_t*)libraryPtr, 50LL);
    if (signatureInst)
    {
        // response_validation|get_parameter|AuthenticationResult_Signature
        int errSig = pfn_get_parameter((int64_t*)libraryPtr, authResultInstance, 128LL, (void*)signatureInst);
        if (errSig != 0)
        {
            freeInstanceIfValid(libraryPtr, signatureInst);
            signatureInst = 0;
        }
    }

    // Build the JSON
    //   { "id":"...", "mdasId":"...", "spId":"...", "nonce":..., "mdasTimestamp":"...", "spTimestamp":"...",
    //     "signature":{...} or {},
    //     "assertion":{...} or omitted,
    //     "resultType":"SUCCESS",
    //     "resultException":(optional)
    //   }
    std::string out = "{";
    out += "\"id\":\"" + id + "\",";
    out += "\"mdasId\":\"" + mdasId + "\",";
    out += "\"spId\":\"" + spId + "\",";
    out += "\"nonce\":" + nonce + ",";
    out += "\"mdasTimestamp\":\"" + mdasTime + "\",";
    out += "\"spTimestamp\":\"" + spTime + "\",";

    // signature
    if (signatureInst)
    {
        std::string sigJson = gatherSignatureJson(libraryPtr, signatureInst);
        freeInstanceIfValid(libraryPtr, signatureInst);
        out += "\"signature\":" + sigJson + ",";
    }
    else
    {
        out += "\"signature\":{},";
    }

    // analysis of function "sub_1400B1A40" is needed for getting resultType string
    // we will go with the integer value for now
    out += "\"resultType\":\"" + std::to_string(m_authenticationResultType) + "\"";

    if (m_authenticationResultType) {
        printf("[+] Ignoring personal info\n");
        // Now paramId=131 => "ResultException" => gather if any
        std::string exJson = gatherResultExceptionJson(libraryPtr, authResultInstance);
        if (!exJson.empty())
        {
            out += ",\"resultException\":" + exJson;
        }
    }
    else {
        printf("[+] Attempting to retrieve personal info\n");
        // paramId=130 => "AuthenticationResult_Assertion" => new instance=100 => then personal info
        int64_t assertionInst = pfn_get_new_instance((int64_t*)libraryPtr, 100LL);
        if (assertionInst)
        {
            // response_validation|get_parameter|AuthenticationResult_Assertion
            int errA = pfn_get_parameter((int64_t*)libraryPtr, authResultInstance, 130LL, (void*)assertionInst);
            if (!errA)
            {
                // According to the IDA snippet, we do "dk_checkAuthentication(...)"
              // and "dk_getLevelOfAssuranceChecks(...)"
              // right before we call CardAuthPersonalInfo.
              // We'll replicate that here:

              // 1) Create new instance paramId=480 => we also read paramId=102 => "Assertion_Loa"
                int64_t loaInstance = pfn_get_new_instance((int64_t*)libraryPtr, 480LL);
                if (loaInstance)
                {
                    // paramId=102 => "Assertion_Loa"
                    int errLoa = pfn_get_parameter((int64_t*)libraryPtr, assertionInst, 102LL, (void*)loaInstance);
                    if (!errLoa)
                    {
                        // call "dk_checkAuthentication"
                        int64_t checkAuthInst = dk_checkAuthentication(libraryPtr);
                        if (checkAuthInst)
                        {
                            // call "dk_getLevelOfAssuranceChecks"
                            int64_t retValue = dk_getLevelOfAssuranceChecks(libraryPtr, checkAuthInst, loaInstance);
                            printf("[+] dk_getLevelOfAssuranceChecks returned = %" PRId64 "\n");
                            freeInstanceIfValid(libraryPtr, checkAuthInst);
                        }
                    }
                    freeInstanceIfValid(libraryPtr, loaInstance);
                }


                // Use the personal info class
                CardAuthPersonalInfo personal;
                std::string personalJson = personal.getPersonalInfoJson(
                    libraryPtr,
                    (int64_t)libraryPtr,
                    assertionInst
                );
                out += "\"assertion\":" + personalJson + ",";

                // Now paramId=131 => "ResultException" => gather if any
                std::string exJson = gatherResultExceptionJson(libraryPtr, authResultInstance);
                if (!exJson.empty())
                {
                    out += ",\"resultException\":" + exJson;
                }
            }
            freeInstanceIfValid(libraryPtr, assertionInst);
        }

    }
    out += "}";
    return out;
}

/**
 * param=50 => signature instance
 * param=52 => signatureAlgorithm
 * param=53 => hashAlgorithm
 * param=54 => algorithmVersion
 * param=56 => CACertificate
 * param=57 => endCertificate
 * param=58 => signatureValue
 * param=55 => DomainParameters
 */
std::string CardAuthResult::gatherSignatureJson(char* libraryPtr, int64_t signatureInstance)
{
    std::string sigAlg = getParamAsString<10244>(libraryPtr, signatureInstance, 52LL, true);
    std::string hashAlg = getParamAsString<10244>(libraryPtr, signatureInstance, 53LL, true);
    std::string algVersion = getParamAsString<10244>(libraryPtr, signatureInstance, 54LL, true);
    std::string caCert = getParamAsString<10244>(libraryPtr, signatureInstance, 56LL, true);
    std::string endCert = getParamAsString<10244>(libraryPtr, signatureInstance, 57LL, true);
    std::string sigValue = getParamAsString<10244>(libraryPtr, signatureInstance, 58LL, true);
    std::string domainParams = getParamAsString<10244>(libraryPtr, signatureInstance, 55LL, true);

    std::string out = "{";
    out += "\"signatureAlgorithm\":\"" + sigAlg + "\",";
    out += "\"hashAlgorithm\":\"" + hashAlg + "\",";
    out += "\"algorithmVersion\":\"" + algVersion + "\",";
    out += "\"CACertificate\":\"" + caCert + "\",";
    out += "\"endCertificate\":\"" + endCert + "\",";
    out += "\"signatureValue\":\"" + sigValue + "\",";
    out += "\"DomainParameters\":\"" + domainParams + "\"";
    out += "}";
    return out;
}

/**
 * paramId=131 => new instance=30 => "ResultException"
 * parse fields => paramId=32..35 => build JSON
 */
std::string CardAuthResult::gatherResultExceptionJson(char* libraryPtr, int64_t authResultInstance)
{
    int64_t exInst = pfn_get_new_instance((int64_t*)libraryPtr, 30LL);
    if (!exInst)
        return std::string();

    // response_validation|get_parameter|AuthenticationResult_ResultException
    int err = pfn_get_parameter((int64_t*)libraryPtr, authResultInstance, 131LL, (void*)exInst);
    if (err != 0)
    {
        pfn_free_instance((int64_t*)libraryPtr, exInst);
        return std::string();
    }

    // category => paramId=32
    // create_json_form_result_exception|get_parameter|ResultException_Category
    CommandParameterStr<10256> catBuf("");
    err = pfn_get_parameter((int64_t*)libraryPtr, exInst, 32LL, (void*)&catBuf);
    if (err) {
        printf("[-] Failed: create_json_form_result_exception|get_parameter|ResultException_Category\n");
    }
    std::string category = std::string(catBuf.str);

    // cause => paramId=33
    // create_json_form_result_exception|get_parameter|ResultException_Cause
    CommandParameterStr<10256> causeBuf("");
    err = pfn_get_parameter((int64_t*)libraryPtr, exInst, 33LL, (void*)&causeBuf);
    if (err) {
        printf("[-] Failed: create_json_form_result_exception|get_parameter|ResultException_Cause\n");
    }
    std::string cause = std::string(causeBuf.str);

    // field => paramId=34
    // create_json_form_result_exception|get_parameter|ResultException_Field
    CommandParameterStr<10256> fieldBuf("");
    err = pfn_get_parameter((int64_t*)libraryPtr, exInst, 34LL, (void*)&fieldBuf);
    if (err) {
        printf("[-] Failed: create_json_form_result_exception|get_parameter|ResultException_Field\n");
    }
    std::string field = std::string(fieldBuf.str);

    // retryCount => paramId=35
    int retryCountVal = 0;
    // create_json_form_result_exception|get_parameter|ResultException_RetryCount
    err = pfn_get_parameter((int64_t*)libraryPtr, exInst, 35LL, (void*)&retryCountVal);
    if (err) {
        printf("[-] Failed: create_json_form_result_exception|get_parameter|ResultException_RetryCount\n");
    }

    freeInstanceIfValid(libraryPtr, exInst);

    std::string out = "{";
    out += "\"category\":\"" + category + "\",";
    out += "\"cause\":\"" + cause + "\",";
    out += "\"field\":\"" + field + "\",";
    out += "\"retryCount\":" + std::to_string(retryCountVal);
    out += "}";
    return out;
}

void CardAuthResult::freeInstanceIfValid(char* libraryPtr, int64_t instance)
{
    if (instance)
        pfn_free_instance((int64_t*)libraryPtr, instance);
}


/**
 * Replicates the IDA code for dk_checkAuthentication(...)
 * Called before retrieving personal info if needed.
 */
int64_t CardAuthResult::dk_checkAuthentication(char* libraryPtr)
{
    // The IDA snippet's logic:
    // if(!dk_ShowFingerPrintUI && ((dk_AuthFingerIndex-2) & 0xFFFFFFFA)==0) { ... checks on finger indexes ... }

    // Check if we skip finger checks or not:
    if (!dk_ShowFingerPrintUI && (((dk_AuthenticationMethod - 2) & 0xFFFFFFFA) == 0))
    {
        // If either finger index is -1 => "First call GetMocFingerIndex..."
        if (dk_FingerIndex1 == -1 || dk_FingerIndex2 == -1)
        {
            throw std::runtime_error(
                "First call GetMocFingerIndex to see whether the citizen has finger or not.");
        }

        // If first finger is 0 => check second
        if (dk_FingerIndex1 == 0)
        {
            if (dk_FingerIndex2 <= 0)
            {
                throw std::runtime_error(
                    "This card has no finger-print and you should authenticate citizen with NMoC PIN. "
                    "please use PIN_PIN authentication method");
            }
            if (dk_fingerStatus2 == 1 && dk_AuthenticationMethod == 3)
            {
                throw std::runtime_error("MoC on finger #2 is Blocked");
            }
        }
        else
        {
            // If finger #1 is blocked => error
            if (dk_fingerStatus1 == 1)
            {
                throw std::runtime_error("MoC on finger #1 is Blocked");
            }
            // If finger #2 is blocked => error
            if (dk_fingerStatus2 == 1 && dk_AuthenticationMethod == 3)
            {
                throw std::runtime_error("MoC on finger #2 is Blocked");
            }
        }
    }

    // Create new instance => paramId=480 => "checkAuthentication"
    int64_t new_instance = pfn_get_new_instance((int64_t*)libraryPtr, 480LL);
    if (!new_instance)
        return 0;

    // param=482 => AuthMethod => dk_AuthFingerIndex
    {
        int err = pfn_set_parameter((int64_t*)libraryPtr, new_instance, 482LL, (void*)&dk_AuthenticationMethod);
        if (err != 0)
        {
            throw std::runtime_error("Failed to set AuthMethod in dk_checkAuthentication(...)");
        }
    }

    // If (dk_AuthFingerIndex in [4..7]) => param=485 => faceMatchingSeverity=3
    if (dk_AuthenticationMethod >= 4 && dk_AuthenticationMethod <= 7)
    {
        int faceMatchingSeverity = 3;
        int err = pfn_set_parameter((int64_t*)libraryPtr, new_instance, 485LL, (void*)&faceMatchingSeverity);
        if (err != 0)
        {
            throw std::runtime_error("Failed to set FaceMatchingSeverity in dk_checkAuthentication(...)");
        }
    }

    // param=483 => revocationCheck => char=1
    {
        char revCheck = 1;
        int err = pfn_set_parameter((int64_t*)libraryPtr, new_instance, 483LL, (void*)&revCheck);
        if (err != 0)
        {
            throw std::runtime_error("Failed to set RevocationCheck in dk_checkAuthentication(...)");
        }
    }

    // param=484 => authorizationCheck => char=0
    {
        char authCheck = 0;
        int err = pfn_set_parameter((int64_t*)libraryPtr, new_instance, 484LL, (void*)&authCheck);
        if (err != 0)
        {
            throw std::runtime_error("Failed to set AuthorizationCheck in dk_checkAuthentication(...)");
        }
    }

    return new_instance;
}

/**
 * Replicates the IDA code for dk_getLevelOfAssuranceChecks(...)
 * Called after checkAuthentication to verify LOA consistency.
 */
int64_t CardAuthResult::dk_getLevelOfAssuranceChecks(char* libraryPtr, int64_t a2, int64_t a3)
{
    // We'll replicate the snippet:
    // mdas_client_get_parameter(rcx0, a3, 482, &authMethod1);
    // ...
    // if(authMethod2==authMethod1 && revCheck2==revCheck1 && authCheck2==authCheck1 && (authMethod2-4)<=3)
    //    return faceSeverity2==faceSeverity1; else return 0;

    int authMethod1 = 0;
    int faceSeverity1 = 0;
    char revCheck1 = 0;
    char authCheck1 = 0;

    // On a3
    {
        pfn_get_parameter((int64_t*)libraryPtr, a3, 482LL, (void*)&authMethod1);
        pfn_get_parameter((int64_t*)libraryPtr, a3, 485LL, (void*)&faceSeverity1);
        pfn_get_parameter((int64_t*)libraryPtr, a3, 483LL, (void*)&revCheck1);
        pfn_get_parameter((int64_t*)libraryPtr, a3, 484LL, (void*)&authCheck1);
    }

    int authMethod2 = 0;
    int faceSeverity2 = 0;
    char revCheck2 = 0;
    char authCheck2 = 0;

    // On a2
    {
        pfn_get_parameter((int64_t*)libraryPtr, a2, 482LL, (void*)&authMethod2);
        pfn_get_parameter((int64_t*)libraryPtr, a2, 485LL, (void*)&faceSeverity2);
        pfn_get_parameter((int64_t*)libraryPtr, a2, 483LL, (void*)&revCheck2);
        pfn_get_parameter((int64_t*)libraryPtr, a2, 484LL, (void*)&authCheck2);
    }

    // If they match => return (faceSeverity2 == faceSeverity1)
    if ((authMethod2 == authMethod1) &&
        (revCheck2 == revCheck1) &&
        (authCheck2 == authCheck1) &&
        (authMethod2 >= 4 && authMethod2 <= 7))
    {
        return (faceSeverity2 == faceSeverity1) ? 1 : 0;
    }

    return 0;
}