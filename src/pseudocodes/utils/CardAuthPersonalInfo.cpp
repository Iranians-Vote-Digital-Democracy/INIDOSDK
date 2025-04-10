#include "CardAuthPersonalInfo.hpp"
#include <cstdio>
#include <cstring>
#include <vector>

/**
 * Replicates dk_GetPersonalInfo_1 pseudocode.
 */
std::string CardAuthPersonalInfo::getPersonalInfoJson(char *libraryPtr,
                                                      int64_t mdasHandle,
                                                      int64_t assertionObj) {
  // (1) Create a new instance paramId=480 => "LoA"
  int64_t loaInst = pfn_get_new_instance((int64_t *)libraryPtr, 480LL);
  if (!loaInst) {
    // Could not create => return empty or "{}"
    return "{}";
  }

  // (2) paramId=102 => "Assertion_Loa" => store into loaInst
  {
    // We can throw on error or just check:
    int err = pfn_get_parameter((int64_t *)libraryPtr, assertionObj, 102LL,
                                (void *)loaInst);
    if (err != 0) {
      printf("[-] Failed: "
             "create_json_form_assertion|get_parameter|Assertion_Loa\n");
      freeInstanceIfValid(libraryPtr, loaInst);
      return "{}";
    }
  }

  // (3) Build the "loa" JSON => replicates dk_CreateJsonFromLoa
  std::string loaJson = createJsonFromLoa(libraryPtr, loaInst);

  // Freed the LoA instance
  freeInstanceIfValid(libraryPtr, loaInst);

  // (4) paramId=103 => "Assertion_ResponseInfo" => typically an array of 64-bit
  // items We read them into a CommandParameterInt64 => each is "responseInfo"
  // paramId

  CommandParameterInt64<32> assertResponseInfo;
  int err = pfn_get_parameter((int64_t *)libraryPtr, assertionObj, 103LL,
                              (void *)&assertResponseInfo);
  if (err) {
    printf("[-] Failed: "
           "create_json_form_assertion|get_parameter|Assertion_ResponseInfo\n");
    freeInstanceIfValid(libraryPtr, loaInst);
    return "{}";
  }

  // (5) Build JSON => { "loa": <loaJson>, "responseInfos": [ ... ] }
  // For each item in respInfos, we call getPersonalInfo0(...) to replicate
  // "dk_GetPersonalInfo_0"
  std::string out;
  out += "{";
  out += "\"loa\":" + loaJson + ",";
  out += "\"responseInfos\":[";
  bool first = true;
  for (int i = 0; i < assertResponseInfo.size; i++) {
    int64_t infoHandle = assertResponseInfo.arr[i];
    if (!first)
      out += ",";
    else
      first = false;

    // The IDA code calls "dk_GetPersonalInfo_0(...)" for each item => returns
    // JSON chunk We'll replicate that. 'infoHandle' is presumably an instance
    // or param? But in the actual IDA snippet, each "info" might be a separate
    // instance => paramId=... For demonstration, we create a new instance
    // paramId=? or we treat 'infoHandle' as the instance itself:
    std::string respJson;
    // If "infoHandle" is 0 => skip. If not => parse
    if (infoHandle != 0) {
      respJson = getPersonalInfo0(libraryPtr, infoHandle);
    } else {
      printf("[-] getPersonalInfoJson: Handle at index %d is 0\n", i);
      respJson = "\"\""; // or empty
    }

    // Place the chunk in the array
    out += respJson;
  }
  out += "]";
  out += "}";

  return out;
}

/**
 * Replicates dk_CreateJsonFromLoa:
 *   - param=482 => AuthenticationMethod
 *   - param=483 => revocationCheck
 *   - param=484 => authorizationCheck
 *   - param=485 => faceMatchingSeverity
 * Builds JSON with these fields.
 */
std::string CardAuthPersonalInfo::createJsonFromLoa(char *libraryPtr,
                                                    int64_t loaInstance) {
  // param=482 => AuthenticationMethod => int
  int authMethod = 0;
  {
    int err = pfn_get_parameter((int64_t *)libraryPtr, loaInstance, 482LL,
                                (void *)&authMethod);
    if (err != 0)
      return "{}";
  }

  // param=483 => revocationCheck => char
  char revocationCheck = 0;
  {
    int err = pfn_get_parameter((int64_t *)libraryPtr, loaInstance, 483LL,
                                (void *)&revocationCheck);
    if (err != 0)
      return "{}";
  }

  // param=484 => authorizationCheck => char
  char authorizationCheck = 0;
  {
    int err = pfn_get_parameter((int64_t *)libraryPtr, loaInstance, 484LL,
                                (void *)&authorizationCheck);
    if (err != 0)
      return "{}";
  }

  // param=485 => faceMatchingSeverity => int
  int faceMatchingSeverity = 0;
  {
    int err = pfn_get_parameter((int64_t *)libraryPtr, loaInstance, 485LL,
                                (void *)&faceMatchingSeverity);
    if (err != 0)
      return "{}";
  }

  // Convert authMethod to string
  std::string authMethodStr = getAuthenticationMethodString(authMethod);

  // Build JSON
  // "create_json_form_loa|get_parameter|LevelOfAssurance_*"
  std::string out;
  out += "{";
  out += "\"authenticationMethod\":\"" + authMethodStr + "\",";
  out += "\"revocationCheck\":" + std::to_string((int)revocationCheck) + ",";
  out +=
      "\"authorizationCheck\":" + std::to_string((int)authorizationCheck) + ",";
  out += "\"faceMatchingSeverity\":" + std::to_string(faceMatchingSeverity);
  out += "}";
  return out;
}

/**
 * Replicates dk_GetAuthenticationMethodString switch-case.
 */
std::string
CardAuthPersonalInfo::getAuthenticationMethodString(int authMethod) {
  switch (authMethod) {
  case 0:
    return "PIN";
  case 1:
    return "PIN_PIN";
  case 2:
    return "PIN_FP";
  case 3:
    return "PIN_FP_FP";
  case 4:
    return "PIN_FACE";
  case 5:
    return "PIN_PIN_FACE";
  case 6:
    return "PIN_FP_FACE";
  case 7:
    return "PIN_FP_FP_FACE";
  default:
    return "";
  }
}

/**
 * This method replicates the IDA pseudocode for "dk_GetPersonalInfo_0(...)":
 *
 * For the sake of demonstration, we assume:
 *   - "responseInfoInstance" is the third param in IDA (a3)
 *   - We read:
 *       param=302 => InfoType
 *       param=304 => Source
 *       param=303 => Value
 *     Then we construct a JSON:
 *        {"infoType":"...", "value":"...", "source":"..."}
 *
 * The actual IDA snippet includes base64, hex, etc. We will place the important
 * lines and comments from the snippet, including references to
 * "create_json_form_response_info|get_parameter|ResponseInfo_InfoType" to
 * preserve the logic.
 */
std::string
CardAuthPersonalInfo::getPersonalInfo0(char *libraryPtr,
                                       int64_t responseInfoInstance) {
  // param=302 => "ResponseInfo_InfoType" => an int
  int infoType = 0;
  {
    // Just like IDA:
    // "create_json_form_response_info|get_parameter|ResponseInfo_InfoType"
    int err = pfn_get_parameter((int64_t *)libraryPtr, responseInfoInstance,
                                302LL, (void *)&infoType);
    if (err != 0) {
      // If error => we can return some minimal
      return "\"\"";
    }
  }

  // param=304 => "ResponseInfo_Source" => also an int
  int source[2];
  source[1] = 0;
  {
    // IDA snippet:
    // "create_json_form_response_info|get_parameter|ResponseInfo_Source"
    int err = pfn_get_parameter((int64_t *)libraryPtr, responseInfoInstance,
                                304LL, source);
    if (err != 0) {
      return "\"\"";
    }
  }

  std::string rawValue;
  if (infoType == 8) {
    CommandParameterStr<65536> valueBuf("");
    int errVal = pfn_get_parameter((int64_t *)libraryPtr, responseInfoInstance,
                                   303LL, (void *)&valueBuf);
    if (errVal != 0) {
      printf(
          "[-] Failed: "
          "create_json_form_response_info|get_parameter|ResponseInfo_Value\n");
      return "\"\"";
    }
    rawValue = std::string(valueBuf.str, valueBuf.size);
  } else {
    CommandParameterStr<10256> valueBuf("");
    int errVal = pfn_get_parameter((int64_t *)libraryPtr, responseInfoInstance,
                                   303LL, (void *)&valueBuf);
    if (errVal != 0) {
      printf(
          "[-] Failed: "
          "create_json_form_response_info|get_parameter|ResponseInfo_Value\n");
      return "\"\"";
    }
    rawValue = std::string(valueBuf.str, strlen(valueBuf.str));
  }

  // If infoType==8 => IDA does base64 => decode => re-encode? We'll skip
  // details, or do placeholders: We'll just place "rawValue" in the JSON.

  // Now build JSON => e.g.:
  // {
  //   "infoType":"(resolved from infoType => e.g. NAME, SURNAME, etc.)",
  //   "value":"(rawValue or processed base64...)",
  //   "source":"(0 => NOCR, 1 => CARD, etc...)"
  // }

  // Convert infoType => string, referencing "dk_NumerToPersonalInfoStr"
  std::string infoTypeStr;
  switch (infoType) {
  case 0:
    infoTypeStr = "NAME";
    break;
  case 1:
    infoTypeStr = "SURNAME";
    break;
  case 2:
    infoTypeStr = "NID";
    break;
  case 3:
    infoTypeStr = "FATHER_NAME";
    break;
  case 4:
    infoTypeStr = "GENDER";
    break;
  case 5:
    infoTypeStr = "DATE_OF_BIRTH";
    break;
  case 6:
    infoTypeStr = "ISSUED_LOCATION";
    break;
  case 7:
    infoTypeStr = "POSTAL_INFO";
    break;
  case 8:
    infoTypeStr = "FACE_INFO";
    break;
  case 9:
    infoTypeStr = "AFIS_CHECKED";
    break;
  case 10:
    infoTypeStr = "IDENTITY_CHANGED";
    break;
  case 11:
    infoTypeStr = "REPLICA";
    break;
  case 12:
    infoTypeStr = "CARD_ISSUANCE_DATE";
    break;
  case 13:
    infoTypeStr = "CARD_EXPIRATION_DATE";
    break;
  default:
    // This might reference byte_1403E9F26 in IDA. We'll just do an empty
    // fallback:
    infoTypeStr = "";
    break;
  }

  // Convert source => string, referencing "dk_SourceToStr"
  std::string sourceStr;
  switch (source[0]) {
  case 0:
    sourceStr = "NOCR";
    break;
  case 1:
    sourceStr = "CARD";
    break;
  case 2:
    sourceStr = "NOCR_PREFERRED";
    break;
  default:
    // fallback
    sourceStr = "";
    break;
  }

  // Build final JSON chunk
  // e.g. { "infoType":"NAME", "value":"rawValue", "source":"NOCR" }
  std::string out;
  out += "{";
  out += "\"infoType\":\"" + infoTypeStr + "\",";
  out += "\"value\":\"" + rawValue + "\",";
  out += "\"source\":\"" + sourceStr + "\"";
  out += "}";

  // We return it as a standard JSON string. The IDA snippet uses further
  // expansions for base64 or hex if infoType==8, etc.
  // We'll keep it relatively simple, unless you want to replicate all the
  // decode/encode steps.

  return out;
}

/**
 * Helper to read param as string or integer (not used here, but you can adapt).
 */
std::string CardAuthPersonalInfo::getParamAsString(char *libraryPtr,
                                                   int64_t instance,
                                                   int64_t paramId,
                                                   bool isString) {
  if (isString) {
    CommandParameterStr<10256> temp("");
    int err = pfn_get_parameter((int64_t *)libraryPtr, instance, paramId,
                                (void *)&temp);
    if (err != 0) {
      return std::string();
    }
    return std::string(temp.str, temp.size);
  } else {
    int val = 0;
    int err = pfn_get_parameter((int64_t *)libraryPtr, instance, paramId,
                                (void *)&val);
    if (err != 0) {
      return "0";
    }
    return std::to_string(val);
  }
}

void CardAuthPersonalInfo::freeInstanceIfValid(char *libraryPtr,
                                               int64_t instance) {
  if (instance) {
    pfn_free_instance((int64_t *)libraryPtr, instance);
  }
}
