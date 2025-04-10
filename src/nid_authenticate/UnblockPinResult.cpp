#include "UnblockPinResult.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>

/**
 * Retrieves the JSON result for UnblockPin.
 */
std::string UnblockPinResult::getUnblockPinResult(char* libraryPtr, int64_t unblockPinV1Instance)
{
    // paramID=670 => "UnblockPinResult"
    int64_t unblockResultInst = pfn_get_new_instance((int64_t*)libraryPtr, 670LL);
    if (!unblockResultInst)
    {
        return "{\"error\":211}";
    }

    // paramID=704 => "UnblockPin_v1_UnblockPinResult"
    int err = pfn_get_parameter((int64_t*)libraryPtr, unblockPinV1Instance, 704LL, (void*)unblockResultInst);
    if (err != 0)
    {
        freeInstanceIfValid(libraryPtr, unblockResultInst);
        std::string msg = dk_getCommandError(err);
        throw std::runtime_error("UnblockPinResult|getUnblockPinResult| could not retrieve 'UnblockPin_v1_UnblockPinResult': " + msg);
    }

    int resultType = getResultType(libraryPtr, unblockResultInst);

    std::string outJson;
    if (resultType == 1)
    {
        std::string exJson = gatherExceptionJson(libraryPtr, unblockResultInst);
        outJson = "{\"resultType\":\"EXCEPTION\",\"resultException\":" + exJson + "}";
    }
    else
    {
        outJson = gatherSuccessJson(libraryPtr, unblockResultInst);
    }

    freeInstanceIfValid(libraryPtr, unblockResultInst);
    return outJson;
}

/**
 * Reads paramID=671 => __int64 => resultType
 */
int UnblockPinResult::getResultType(char* libraryPtr, int64_t unblockPinResultInstance)
{
    int resultType = 0;
    int err = pfn_get_parameter((int64_t*)libraryPtr, unblockPinResultInstance, 671LL, (void*)&resultType);
    if (err != 0) {
        printf("[-] CardAuthResult::getResultType failed | err = %d | resultType = %d \n", err, resultType);
    }
    return resultType;
}

/**
 * If resultType=1 => build exception JSON
 * We create paramID=30 => "ResultException"
 * Then paramID=672 => "UnblockPinResult_ResultException"
 * Then read paramID=32..35 => category, cause, field (strings), retryCount (int64)
 */
std::string UnblockPinResult::gatherExceptionJson(char* libraryPtr, int64_t unblockPinResultInstance)
{
    int64_t exInst = pfn_get_new_instance((int64_t*)libraryPtr, 30LL);
    if (!exInst)
    {
        return "{\"category\":\"\",\"cause\":\"\",\"field\":\"\",\"retryCount\":0}";
    }

    int err = pfn_get_parameter((int64_t*)libraryPtr, unblockPinResultInstance, 672LL, (void*)exInst);
    if (err != 0)
    {
        freeInstanceIfValid(libraryPtr, exInst);
        return "{\"category\":\"\",\"cause\":\"\",\"field\":\"\",\"retryCount\":0}";
    }

    std::string category = readParamAsString(libraryPtr, exInst, 32LL, 10256);
    std::string cause = readParamAsString(libraryPtr, exInst, 33LL, 10256);
    std::string field = readParamAsString(libraryPtr, exInst, 34LL, 10256);

    int retryCountVal = 0;
    err = pfn_get_parameter((int64_t*)libraryPtr, exInst, 35LL, (void*)&retryCountVal);
    if (err) {
        printf("[-] Failed: create_json_form_result_exception|get_parameter|ResultException_RetryCount\n");
    }
    freeInstanceIfValid(libraryPtr, exInst);

    std::string out = "{\"category\":\"" + category + "\",\"cause\":\"" + cause + "\",\"field\":\"" + field
        + "\",\"retryCount\":" + std::to_string(retryCountVal) + "}";
    return out;
}

/**
 * If resultType=0 => gather success
 *   paramID=673 => Id (string up to 10244)
 *   paramID=674 => MdasId (string up to 10244)
 *   paramID=675 => Nonce => __int64
 *   paramID=676 => SpId (string up to 10256)
 *   paramID=677 => MdasTimestamp (string up to 10244)
 *   paramID=678 => SpTimestamp (string up to 10244)
 *   paramID=679 => signature => paramID=50 => gatherSignatureJson
 */
std::string UnblockPinResult::gatherSuccessJson(char* libraryPtr, int64_t unblockPinResultInstance)
{
    std::string id = readParamAsString(libraryPtr, unblockPinResultInstance, 673LL, 10244);
    std::string mdasId = readParamAsString(libraryPtr, unblockPinResultInstance, 674LL, 10244);
    int64_t     nonceVal = readParamAsUInt64(libraryPtr, unblockPinResultInstance, 675LL);
    std::string spId = readParamAsString(libraryPtr, unblockPinResultInstance, 676LL, 10256);
    std::string mdasTime = readParamAsString(libraryPtr, unblockPinResultInstance, 677LL, 10244);
    std::string spTime = readParamAsString(libraryPtr, unblockPinResultInstance, 678LL, 10244);

    // param=679 => signature => paramID=50
    int64_t signatureInst = pfn_get_new_instance((int64_t*)libraryPtr, 50LL);
    bool hasSignature = false;
    if (signatureInst)
    {
        int errSig = pfn_get_parameter((int64_t*)libraryPtr, unblockPinResultInstance, 679LL, (void*)signatureInst);
        if (errSig == 0)
            hasSignature = true;
        else
        {
            freeInstanceIfValid(libraryPtr, signatureInst);
            signatureInst = 0;
        }
    }

    std::string out = "{\"resultType\":\"SUCCESS\",";
    out += "\"id\":\"" + id + "\",";
    out += "\"mdasId\":\"" + mdasId + "\",";
    out += "\"nonce\":" + std::to_string(nonceVal) + ",";
    out += "\"spId\":\"" + spId + "\",";
    out += "\"mdasTimestamp\":\"" + mdasTime + "\",";
    out += "\"spTimestamp\":\"" + spTime + "\",";

    if (hasSignature)
    {
        std::string sigJson = gatherSignatureJson(libraryPtr, signatureInst);
        freeInstanceIfValid(libraryPtr, signatureInst);
        out += "\"signature\":" + sigJson;
    }
    else
    {
        out += "\"signature\":{}";
    }

    out += "}";
    return out;
}

/**
 * Gathers signature data => paramID=50 => "Signature"
 *   paramID=52 => up to 10244 => signatureAlgorithm
 *   paramID=53 => up to 10244 => hashAlgorithm
 *   paramID=54 => up to 10244 => algorithmVersion
 *   paramID=55 => up to 10244 => DomainParameters
 *   paramID=56 => up to 10244 => CACertificate
 *   paramID=57 => up to 10244 => endCertificate
 *   paramID=58 => up to 10244 => signatureValue
 */
std::string UnblockPinResult::gatherSignatureJson(char* libraryPtr, int64_t signatureInstance)
{
    std::string sigAlg = readParamAsString(libraryPtr, signatureInstance, 52LL, 10244);
    std::string hashAlg = readParamAsString(libraryPtr, signatureInstance, 53LL, 10244);
    std::string algVer = readParamAsString(libraryPtr, signatureInstance, 54LL, 10244);
    std::string domain = readParamAsString(libraryPtr, signatureInstance, 55LL, 10244);
    std::string caCert = readParamAsString(libraryPtr, signatureInstance, 56LL, 10244);
    std::string endCert = readParamAsString(libraryPtr, signatureInstance, 57LL, 10244);
    std::string sigValue = readParamAsString(libraryPtr, signatureInstance, 58LL, 10244);

    std::string out = "{";
    out += "\"signatureAlgorithm\":\"" + sigAlg + "\",";
    out += "\"hashAlgorithm\":\"" + hashAlg + "\",";
    out += "\"algorithmVersion\":\"" + algVer + "\",";
    out += "\"CACertificate\":\"" + caCert + "\",";
    out += "\"endCertificate\":\"" + endCert + "\",";
    out += "\"signatureValue\":\"" + sigValue + "\",";
    out += "\"DomainParameters\":\"" + domain + "\"";
    out += "}";
    return out;
}

/**
 * Frees an instance if not zero.
 */
void UnblockPinResult::freeInstanceIfValid(char* libraryPtr, int64_t instance)
{
    if (instance)
    {
        pfn_free_instance((int64_t*)libraryPtr, instance);
    }
}

/**
 * Reads a parameter as a string if IDA shows a char buffer.
 * We pass the buffer size from the disassembly (e.g., 10244 or 10256).
 */
std::string UnblockPinResult::readParamAsString(char* libraryPtr, int64_t instance, int64_t paramId, size_t bufferSize)
{
    // e.g., char arr[10256]
    std::vector<char> buffer(bufferSize, '\0');

    int err = pfn_get_parameter((int64_t*)libraryPtr, instance, paramId, buffer.data());
    if (err != 0)
    {
        return "";
    }

    // The structure is typically { char str[N]; int size; } in your code,
    // but if we see just a raw char array in IDA, we store ASCII + null
    // So let's assume it's a null-terminated string in that memory.
    // We'll do a safe check for the null terminator.
    buffer[bufferSize - 1] = '\0';

    // Build std::string from null-terminated region
    return std::string(buffer.data());
}

uint64_t UnblockPinResult::readParamAsUInt64(char* libraryPtr, int64_t instance, int64_t paramId)
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