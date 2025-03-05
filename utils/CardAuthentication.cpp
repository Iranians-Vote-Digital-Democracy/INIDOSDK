#include "CardAuthentication.hpp"
#include <random>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <windows.h>      // For WinHttp*, CryptBinaryToStringW, etc.
#include <winhttp.h>
#include <vector>
#include <stdexcept>
#include <iostream>
#include <inttypes.h>
#pragma comment(lib, "winhttp.lib")
#pragma comment(lib, "crypt32.lib")

int ConnnectToCardAndDoNothing();

// Suppose these are the global strings the reversed code references
// (like qword_1404BEE98, qword_1404BEEB8, etc.)
static const char* g_signatureAlgorithm = "1.2.840.113549.1.1.11";     
static const char* g_hashAlgorithm = "2.16.840.1.101.3.4.2.1";
static const char* g_algorithmVersion = "1.00";  

// (Optionally define or extern any spId or server address here.)
// For example:
//   std::string dk_SpSignatureServerAddress = "http://127.0.0.1/spSignature";
//   std::string dk_setSpSignature_spId      = "MyServiceProviderID";

bool CardAuthentication::CardAuthenticate(int64_t /*rcx0*/, char* libraryPtr)
{
    //printf("[+] press any key to call setParametersCardAuthenticate\n");
    //getchar();

    // Create the “Authenticate_v1” instance
    int64_t newAuthInstance = setParametersCardAuthenticate(libraryPtr);
    m_authV1Instance = newAuthInstance; // if you forget to free this after use, you get a nice CRASH
    if (!newAuthInstance)
    {
        // Means something failed
        return false;
    }
     
    // Execute => "authenticate_service|execute|Authenticate_v1"
    std::string cmd = "authenticate_service|execute|Authenticate_v1";
    std::cout << "[+] " << cmd << " => about to execute\n";

    printf("[+] press any key to continue\n");
    getchar();
    //ConnnectToCardAndDoNothing();

    int err = pfn_execute((int64_t*)libraryPtr, newAuthInstance);
    if (err != 0)
    {
        std::string msg = cmd + "| error: " + dk_getCommandError(err);
        throw std::runtime_error(msg);
    }
    std::cout << "[+] CardAuthenticate completed successfully\n";
    return true;
}

int64_t CardAuthentication::setParametersCardAuthenticate(char* libraryPtr)
{

    int64_t loaInstance = checkAuthentication(libraryPtr);
    if (!loaInstance) return 0;

    int64_t credentialsInstance = setFaceDataCredentials(libraryPtr);
    int64_t scopeInstance = setRequiredInfo(libraryPtr); 
    int64_t spSignatureInstance = setSpSignature(libraryPtr);
    printf("spSignatureInstance = %" PRId64 "\n", spSignatureInstance);

    // Create the “Authenticate_v1” => paramID=630
    int64_t newAuthInstance = pfn_get_new_instance((int64_t*)libraryPtr, 630LL);
    if (!newAuthInstance)
    {
        freeInstanceIfValid(libraryPtr, loaInstance);
        freeInstanceIfValid(libraryPtr, credentialsInstance);
        freeInstanceIfValid(libraryPtr, scopeInstance);
        freeInstanceIfValid(libraryPtr, spSignatureInstance);
        return 0;
    } 
      
    // paramId=632 => LoA
    setParameterOrThrowNoPointer(libraryPtr, newAuthInstance, 632LL, loaInstance,
        "set_authentication_service_parameters|set_parameter|Authenticate_v1_Loa");

    // paramId=633 => Credentials
   setParameterOrThrowNoPointer(libraryPtr, newAuthInstance, 633LL, credentialsInstance,
        "set_authentication_service_parameters|set_parameter|Authenticate_v1_Credentials");

    // paramId=634 => Scope
    setParameterOrThrowNoPointer(libraryPtr, newAuthInstance, 634LL, scopeInstance,
        "set_authentication_service_parameters|set_parameter|Authenticate_v1_Scope");


    // paramId=635 => SpSignature
    if (spSignatureInstance)
    {
        setParameterOrThrowNoPointer(libraryPtr, newAuthInstance, 635LL, spSignatureInstance,
            "set_authentication_service_parameters|set_parameter|Authenticate_v1_SpSignature");
    }
    // cleanup
    freeInstanceIfValid(libraryPtr, loaInstance);
    freeInstanceIfValid(libraryPtr, credentialsInstance);
    freeInstanceIfValid(libraryPtr, scopeInstance);
    freeInstanceIfValid(libraryPtr, spSignatureInstance);

    return newAuthInstance;
}

int64_t CardAuthentication::checkAuthentication(char* libraryPtr)
{
    // paramId=480 => “checkAuthentication” instance
    int64_t newInstance = pfn_get_new_instance((int64_t*)libraryPtr, 480LL);
    if (!newInstance) return 0;

    // paramId=482 => AuthMethod => dk_AuthFingerIndex
    setParameterOrThrow(libraryPtr, newInstance, 482LL, dk_AuthenticationMethod,
        "set_level_of_assurance|set_parameter|LevelOfAssurance_AuthenticationMethod");

    // paramId=483 => revocationCheck => 1
    {
        char revCheck = 1;
        setParameterOrThrow(libraryPtr, newInstance, 483LL, revCheck,
            "set_level_of_assurance|set_parameter|LevelOfAssurance_RevocationCheck");
    }

    // paramId=484 => authorizationCheck => 0
    {
        char authCheck = 0;
        setParameterOrThrow(libraryPtr, newInstance, 484LL, authCheck,
            "set_level_of_assurance|set_parameter|LevelOfAssurance_AuthorizationCheck");
    }

    return newInstance;
}


int64_t CardAuthentication::setFaceDataCredentials(char* libraryPtr)
{
    // paramID=350 => new credentials instance
    int64_t new_instance = pfn_get_new_instance((int64_t*)libraryPtr, 350LL);
    if (!new_instance)
    {
        return 0; // fail
    }
    
    // If user does NOT want FingerPrint UI, then set fingerprint data
    if (!dk_ShowFingerPrintUI)
    {
        // The reversed code calls: dk_SetCredentialsFingerPrint(...)
        // We'll implement that logic in a helper method:
        int64_t outFinger1 = 0;
        int64_t outFinger2 = 0;
       // printf("[ WARNING ] Skipping call to setCredentialsFingerPrint\n");
        setCredentialsFingerPrint(libraryPtr, new_instance, dk_AuthenticationMethod, outFinger1, outFinger2);
          
        // Freed at the end:
        freeInstanceIfValid(libraryPtr, outFinger1);
        freeInstanceIfValid(libraryPtr, outFinger2);
    }

    // If user does NOT want Face Input UI, AND (dk_AuthFingerIndex in [4..7]),
    // the reversed code calls "dk_set_face_data(a1)" => sets param=356 => Credentials_FaceData
    if (!dk_ShowFaceInputUI && (dk_AuthenticationMethod >= 4 && dk_AuthenticationMethod <= 7))
    {
        // Stub for setFaceData (can be empty or do something if needed)
        int64_t faceInstance = setFaceData(libraryPtr);
        if (faceInstance)
        {
            setParameterOrThrowNoPointer(libraryPtr, new_instance, 356LL, faceInstance,
                "set_credentials|set_parameter|Credentials_FaceData");
            freeInstanceIfValid(libraryPtr, faceInstance);
        }
    }

    return new_instance;
}
 
void CardAuthentication::setCredentialsFingerPrint(
    char* libraryPtr,
    int64_t credentialsInstance,
    int authFingerIndex,
    int64_t& outFinger1, 
    int64_t& outFinger2)
{
    // The IDA logic checks: ((authFingerIndex - 2) & 0xFFFFFFFA) == 0, etc.
    // but we'll do a simpler approach:

    bool usedFirstFinger = false;
    printf("setCredentialsFingerPrint called\n");
    // Attempt first finger (dk_FingerIndex1) if > 0
    if (dk_FingerIndex1 > 0)
    {
        outFinger1 = setFingerPrintData(libraryPtr, dk_FingerIndex1);
        if (outFinger1 == 0)
        {
            throw std::runtime_error("Failed to set first finger-print data");
        }
        // param=353 => Credentials_FingerPrint_1
        setParameterOrThrowNoPointer(libraryPtr, credentialsInstance, 353LL, outFinger1,
            "set_credentials_finger|set_parameter|Credentials_FingerPrint_1");
        usedFirstFinger = true;
    }
    // If we need a second finger => (authFingerIndex == 3 || authFingerIndex == 7)
    if ((authFingerIndex == 3) || (authFingerIndex == 7))
    {
        if (dk_FingerIndex2 <= 0)
        {
            throw std::runtime_error("This card has no second finger MoC");
        }
        outFinger2 = setFingerPrintData(libraryPtr, dk_FingerIndex2);
        if (outFinger2 == 0)
        {
            throw std::runtime_error("Failed to set second finger-print data");
        }
        // param=354 => Credentials_FingerPrint_2
        setParameterOrThrowNoPointer(libraryPtr, credentialsInstance, 354LL, outFinger2,
            "set_credentials_finger|set_parameter|Credentials_FingerPrint_2");
    }
    else
    {
        // If no second finger is needed, but first wasn't used => throw
        if (!usedFirstFinger)
        {
            throw std::runtime_error(
                "This card has no finger-print and you should authenticate "
                "citizen with NMoC PIN. Please use PIN_PIN authentication method.");
        }
    }
}

int64_t CardAuthentication::setFingerPrintData(char* libraryPtr, int fingerIndex)
{
    int64_t newInst = pfn_get_new_instance((int64_t*)libraryPtr, 320LL);
    if (!newInst) return 0;

    // param=322 => FingerIndex
    setParameterOrThrow(libraryPtr, newInst, 322LL, fingerIndex,
        "set_finger_print|set_parameter|FingerPrint_FingerIndex");

    // param=323 => FingerDataType => 0
    int dataType = 0;
    setParameterOrThrow(libraryPtr, newInst, 323LL, dataType,
        "set_finger_print|set_parameter|FingerPrint_FingerDataType");

    // If dataType == 0, we must supply raw finger data
    // Instead of base64 from memory, let's read from "finger_print.bmp"
    std::vector<char> fileData;
    {
        FILE* f = std::fopen("finger_print.bmp", "rb");
        if (!f)
        {
            throw std::runtime_error("Could not open finger_print.bmp");
        }
        std::fseek(f, 0, SEEK_END);
        long fsize = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);
        if (fsize <= 0)
        {
            fclose(f);
            throw std::runtime_error("finger_print.bmp is empty or error reading size");
        }
        fileData.resize(static_cast<size_t>(fsize));
        std::fread(fileData.data(), 1, static_cast<size_t>(fsize), f);
        fclose(f);
    }

    // We need a small struct to hold (pointer, size)
    struct FingerDataParam {
        void* dataPtr;
        int   size;
    } paramData{ fileData.data(), static_cast<int>(fileData.size()) };

    printf("fileData.data() = %p | fileData.size() = %" PRId64 "\n", 
        fileData.data(), fileData.size());

    // param=324 => raw finger data
    setParameterOrThrow(libraryPtr, newInst, 324LL, paramData,
        "set_finger_print|set_parameter|FingerPrint_FingerData");

    // param=325 => imageWidth => from your global or just 320
    int imageWidth = 320;
    setParameterOrThrow(libraryPtr, newInst, 325LL, imageWidth,
        "set_finger_print|set_parameter|FingerPrint_ImageWidth");

    // param=326 => imageHeight => from your global or 480
    int imageHeight = 480;
    setParameterOrThrow(libraryPtr, newInst, 326LL, imageHeight,
        "set_finger_print|set_parameter|FingerPrint_ImageHeight");

    // param=327 => resolution => from your global or 512
    int resolution = 512;
    setParameterOrThrow(libraryPtr, newInst, 327LL, resolution,
        "set_finger_print|set_parameter|FingerPrint_Resolution");

    return newInst;
}

int64_t CardAuthentication::setFaceData(char* libraryPtr)
{
    // 1) Create a new instance => paramID=657
    int64_t newInst = pfn_get_new_instance((int64_t*)libraryPtr, 657LL);
    if (!newInst)
    {
        return 0; // if it fails, return 0
    }

    // 2) Read the raw face image from "face_image.bmp"
    //    (Adjust filename or path as appropriate.)
    std::vector<char> fileData;
    {
        FILE* f = std::fopen("face_image.bmp", "rb");
        if (!f)
        {
            throw std::runtime_error("Could not open face_image.bmp");
        }
        std::fseek(f, 0, SEEK_END);
        long fsize = std::ftell(f);
        std::fseek(f, 0, SEEK_SET);
        if (fsize <= 0)
        {
            std::fclose(f);
            throw std::runtime_error("face_image.bmp is empty or error reading size");
        }
        fileData.resize(static_cast<size_t>(fsize));
        std::fread(fileData.data(), 1, static_cast<size_t>(fsize), f);
        std::fclose(f);
    }

    // 3) Supply the raw face image data to param=661 (FaceData_pProbeImgData).
    //    Just like with fingerprint data, we wrap the pointer and size in a small struct.
    struct FaceDataParam
    {
        void* dataPtr;
        int   size;
    } faceParam{ fileData.data(), static_cast<int>(fileData.size()) };

    setParameterOrThrow(libraryPtr, newInst, 661LL, faceParam,
        "set_face_data|set_parameter|FaceData_pProbeImgData");

    // 4) Set param=658 => faceWidth
    //    (In the IDA snippet, it was a 4-byte buffer 'v23'. We'll just supply an int.)
    int faceWidth = 320;
    setParameterOrThrow(libraryPtr, newInst, 658LL, faceWidth,
        "set_face_data|set_parameter|FaceData_nProbeImgWidth");

    // 5) Set param=659 => faceHeight
    int faceHeight = 240;
    setParameterOrThrow(libraryPtr, newInst, 659LL, faceHeight,
        "set_face_data|set_parameter|FaceData_nProbeImgHeight");

    // 6) Set param=660 => faceStride
    //    Typically stride = width * bytesPerPixel (plus alignment).
    //    If your BMP is 24 bits per pixel => that’s 3 bytes/pixel. For 320 width, that’s ~960.
    //    Adjust as needed. For demonstration:
    int faceStride = 960;
    setParameterOrThrow(libraryPtr, newInst, 660LL, faceStride,
        "set_face_data|set_parameter|FaceData_nProbeImgStride");

    // 7) Return the new instance
    return newInst;
}

int64_t CardAuthentication::setRequiredInfo(char* libraryPtr)
{
    // paramID=260 => "Scope" instance
    int64_t newInst = pfn_get_new_instance((int64_t*)libraryPtr, 260LL);
    if (!newInst) return 0;
    printf("setRequiredInfo 1\n");
    // paramId=262 => Scope_Source => 1
    {
        int scopeSource = 1;
        setParameterOrThrow(libraryPtr, newInst, 262LL, scopeSource,
            "set_scope|set_parameter|Scope_Source");
    }
    printf("setRequiredInfo 2\n");
    // Now create 9 “RequiredCitizenInfo”
    int64_t rci0 = setRequiredCitizenInfo(libraryPtr, 0, 1);
    int64_t rci1 = setRequiredCitizenInfo(libraryPtr, 1, 1);
    int64_t rci2 = setRequiredCitizenInfo(libraryPtr, 2, 1);
    int64_t rci3 = setRequiredCitizenInfo(libraryPtr, 3, 1);
    int64_t rci5 = setRequiredCitizenInfo(libraryPtr, 5, 1);
    int64_t rci4 = setRequiredCitizenInfo(libraryPtr, 4, 1);
    int64_t rci7 = setRequiredCitizenInfo(libraryPtr, 7, 1);
    int64_t rci6 = setRequiredCitizenInfo(libraryPtr, 6, 1);
    int64_t rci8 = setRequiredCitizenInfo(libraryPtr, 8, 0);
    //printf("rci0: %lld, rci1: %lld, rci2: %lld, rci3: %lld, rci4: %lld, rci5: %lld, rci6: %lld, rci7: %lld, rci8: %lld\n",
    //    rci0, rci1, rci2, rci3, rci4, rci5, rci6, rci7, rci8);

    int64_t citizenInfos[9] = { rci0, rci1, rci2, rci3, rci5, rci4, rci7, rci6, rci8 };
    CommandParameterInt64<32> p_citizenInfos(citizenInfos, 9);
   // printf("%p | %p\n", p_citizenInfos.arr, &p_citizenInfos.size);
    printf("o1\n");
    setParameterOrThrow(libraryPtr, newInst, 263LL, p_citizenInfos,
        "set_scope|set_parameter|Scope_RequiredCitizenInfo");
       
    // free them
    freeInstanceIfValid(libraryPtr, rci0);
    freeInstanceIfValid(libraryPtr, rci1);
    freeInstanceIfValid(libraryPtr, rci2);
    freeInstanceIfValid(libraryPtr, rci3);
    freeInstanceIfValid(libraryPtr, rci5);
    freeInstanceIfValid(libraryPtr, rci4);
    freeInstanceIfValid(libraryPtr, rci7);
    freeInstanceIfValid(libraryPtr, rci6);
    freeInstanceIfValid(libraryPtr, rci8);

    // Then 5 “SupplementInfo”
    int64_t s1 = setSupplementInfo(libraryPtr, 9);
    int64_t s2 = setSupplementInfo(libraryPtr, 10);
    int64_t s3 = setSupplementInfo(libraryPtr, 11); 
    int64_t s4 = setSupplementInfo(libraryPtr, 12);
    int64_t s5 = setSupplementInfo(libraryPtr, 13);
     
    int64_t suppInfos[5] = { s1, s2, s3, s4, s5 };
    CommandParameterInt64<32> p_suppInfos(suppInfos, 5);
    printf("o2\n");
    setParameterOrThrow(libraryPtr, newInst, 264LL, p_suppInfos,
        "set_scope|set_parameter|Scope_RequiredSecSupplementaryInfo");
    printf("o3\n");
    // free them
    freeInstanceIfValid(libraryPtr, s1);
    freeInstanceIfValid(libraryPtr, s2);
    freeInstanceIfValid(libraryPtr, s3);
    freeInstanceIfValid(libraryPtr, s4);
    freeInstanceIfValid(libraryPtr, s5);

    return newInst;
}

int64_t CardAuthentication::setRequiredCitizenInfo(char* libraryPtr, int infoType, char isMandatory)
{
    // paramID=280 => newInst
    int64_t newInst = pfn_get_new_instance((int64_t*)libraryPtr, 280LL);
    if (!newInst) return 0;

    // paramId=282 => infoType
    setParameterOrThrow(libraryPtr, newInst, 282LL, infoType,
        "set_required_citizen_info|set_parameter|RequestedCitizenInfo_InfoType");

    // paramId=283 => isMandatory
    setParameterOrThrow(libraryPtr, newInst, 283LL, isMandatory,
        "set_required_citizen_info|set_parameter|RequestedCitizenInfo_IsMandatory");

    return newInst;
}

int64_t CardAuthentication::setSupplementInfo(char* libraryPtr, int infoType)
{
    // paramID=590 => newInst
    int64_t newInst = pfn_get_new_instance((int64_t*)libraryPtr, 590LL);
    if (!newInst) return 0;

    // paramId=592 => infoType
    setParameterOrThrow(libraryPtr, newInst, 592LL, infoType,
        "set_parameter|SupplementInfo_InfoType");
    return newInst;
}

int64_t CardAuthentication::setSpSignature(char* libraryPtr)
{
    // 1) generate nonce => sub_1400B0FB0 => store into *a2
    printf("setSpSignature 1\n");
    uint64_t nonce = generateNonce();
    printf("setSpSignature 2\n");
    // 2) get iso8601 => "dk_format_ISO_8601"
    std::string isoTime = formatIso8601();
    printf("setSpSignature 3\n");
    // 3) do "dk_SetSpSignatureData" => returns sub-instance handle
    int64_t signDataHandle = setSpSignatureData(libraryPtr);
    if (!signDataHandle)
    {
        // if zero => no signature
        return 0;
    }

    // paramId=80 => "SpSignature" instance
    int64_t new_instance = pfn_get_new_instance((int64_t*)libraryPtr, 80LL);
    if (!new_instance)
    {
        freeInstanceIfValid(libraryPtr, signDataHandle);
        return 0;
    }


    // paramId=85 => signDataHandle
    setParameterOrThrowNoPointer(libraryPtr, new_instance, 85LL, signDataHandle,
        "set_sp_signature|set_parameter|SpSignature_Signature");

    // paramId=82 => spId => from some global or stub. For now we use a placeholder:
    {
        CommandParameterStr<10244> spId("MyServiceProviderID");
        setParameterOrThrow(libraryPtr, new_instance, 82LL, spId,
            "set_sp_signature|set_parameter|SpSignature_SpId");
    } 

    // paramId=83 => Nonce => we pass (char*)a2 or a2 itself
    setParameterOrThrow(libraryPtr, new_instance, 83LL, nonce,
        "set_sp_signature|set_parameter|SpSignature_Nonce");

    // paramId=84 => Timestamp => isoTime
    {
        CommandParameterStr<10244> ts(isoTime.c_str());
        setParameterOrThrow(libraryPtr, new_instance, 84LL, ts,
            "set_sp_signature|set_parameter|SpSignature_Timestamp");
    }

    // free the signDataHandle
    freeInstanceIfValid(libraryPtr, signDataHandle);
    return new_instance;
}
 
// ---------------------------------------------------------------------------
// Private Extra Methods
// ---------------------------------------------------------------------------

// sub_1400B0FB0 => create random nonce => store in *a2
uint64_t CardAuthentication::generateNonce()
{
    // The reversed code uses a Mersenne Twister approach, but for simplicity:
    std::random_device rd;
    uint64_t val = ((uint64_t)rd() << 32) ^ rd();

    // We store it in *a2. Alternatively, you might want to store a pointer,
    // but let's store it as the numeric cast:
    return val;
}

// Minimal ISO8601
//std::string CardAuthentication::formatIso8601()
//{
//    using namespace std::chrono;
//    auto now = system_clock::now();
//    auto tt = system_clock::to_time_t(now);
//    auto micros = duration_cast<microseconds>(now.time_since_epoch()).count() % 1000000;
//
//    std::tm tmBuf;
//    gmtime_s(&tmBuf, &tt);
//
//    std::ostringstream oss;
//    oss << std::put_time(&tmBuf, "%Y-%m-%dT%H:%M:%S")
//        << '.' << std::setw(6) << std::setfill('0') << micros
//        << 'Z';
//
//    return oss.str();
//}

std::string CardAuthentication::formatIso8601()
{
    using namespace std::chrono;
    auto now = system_clock::now();
    auto tt = system_clock::to_time_t(now);

    std::tm tmBuf; 
    gmtime_s(&tmBuf, &tt);

    std::ostringstream oss;
    // Day-Month-Year T Hour:Minute:Second z
    oss << std::put_time(&tmBuf, "%d-%m-%YT%H:%M:%S") << 'z';

    return oss.str();
}

static bool dk_GetSpSignatureValueHTTP(
    const std::string& serverName,
    /*other params if needed...*/
    std::vector<uint8_t>& outSignatureBytes)
{
    // For demonstration, let's pretend we successfully do an HTTP POST,
    // then fill outSignatureBytes with something (like “Hello from server”).
    // In the real reversed code, it used WinHttpOpen, WinHttpConnect, etc.
    // We'll just do a small stub:
    std::string fakeServerResponse = "HelloFromServer";
    outSignatureBytes.assign(fakeServerResponse.begin(), fakeServerResponse.end());
    return true; // success
}


// Stub for base64 conversion (like your "dk_ToBase64String(...)")
std::string CardAuthentication::dk_ToBase64String(const uint8_t* data, size_t dataSize)
{
    if (!data || dataSize == 0)
    {
        // No data => return empty string
        return std::string();
    }

    // 1) Call once to get required wide buffer length (pcchString)
    DWORD pcchString = 0;
    BOOL ok = CryptBinaryToStringW(
        data,
        static_cast<DWORD>(dataSize),
        CRYPT_STRING_BASE64_NOCRLF,  // 0x40000001 => Base64 without line-breaks
        nullptr,
        &pcchString
    );
    if (!ok || pcchString == 0)
    {
        // Something failed
        return std::string();
    }

    // 2) Allocate a std::wstring of length pcchString (includes null terminator)
    std::wstring wideBase64;
    // pcchString is a count of wide chars
    wideBase64.resize(pcchString);

    // 3) Second call writes the wide Base64 string (including the trailing null)
    ok = CryptBinaryToStringW(
        data,
        static_cast<DWORD>(dataSize),
        CRYPT_STRING_BASE64_NOCRLF,
        &wideBase64[0],
        &pcchString
    );
    if (!ok)
    {
        // If we can't encode, return empty
        return std::string();
    }

    // 4) The last character is likely L'\0'. We can remove it for a clean wstring
    if (!wideBase64.empty() && wideBase64.back() == L'\0')
    {
        wideBase64.pop_back(); // remove the null terminator
    }

    // 5) Convert wideBase64 (UTF-16) to a UTF-8 std::string
    //    Use WideCharToMultiByte:
    int utf8Size = WideCharToMultiByte(
        CP_UTF8,
        0,
        wideBase64.c_str(),
        static_cast<int>(wideBase64.size()),
        nullptr,
        0,
        nullptr,
        nullptr
    );
    if (utf8Size <= 0)
    {
        return std::string();
    }

    std::string result;
    result.resize(utf8Size);

    WideCharToMultiByte(
        CP_UTF8,
        0,
        wideBase64.c_str(),
        static_cast<int>(wideBase64.size()),
        &result[0],
        utf8Size,
        nullptr,
        nullptr
    );

    return result;
}

int64_t CardAuthentication::setSpSignatureData(char* libraryPtr, const std::string& inputData)
{
    // 1) Create new_instance => paramId=50
    printf("setSpSignatureData called\n");
    int64_t new_instance = pfn_get_new_instance((int64_t*)libraryPtr, 50LL);
    if (!new_instance)
    {
        return 0; // fail
    }
    // 2) Possibly build or parse "inputData" if needed.
    //    The reversed snippet had "rdx0" plus "data=...&workerName=..."
    //    We'll skip the complex string manipulation and proceed to the HTTP step.

    // 3) HTTP => retrieve raw signature bytes
    std::vector<uint8_t> signatureBytes;
    bool httpOk = dk_GetSpSignatureValueHTTP(
        /*serverName=*/"127.0.0.1:8080",  // or your real server
        /*...*/
        signatureBytes
    );
    if (!httpOk || signatureBytes.empty())
    {
        // If HTTP fails, we skip => free new_instance => return 0
        freeInstanceIfValid(libraryPtr, new_instance);
        return 0;
    }

    // 4) Convert those bytes to base64
    std::string base64Signature = dk_ToBase64String(signatureBytes.data(), signatureBytes.size());

    // 5) Now set these param IDs on the new_instance:
    //    paramId=52 => "Signature_SignatureAlgorithm"
    //    paramId=53 => "Signature_HashAlgorithm"
    //    paramId=54 => "Signature_AlgorithmVersion"
    //    paramId=58 => "Signature_SignatureValue"

    // 5a) paramId=52 => signatureAlgorithm
    {
        CommandParameterStr<10244> alg(g_signatureAlgorithm);
        setParameterOrThrow(libraryPtr, new_instance, 52LL, alg,
            "set_signature|set_parameter|Signature_SignatureAlgorithm");
    }

    // 5b) paramId=53 => hashAlgorithm
    {
        CommandParameterStr<10244> hashAlg(g_hashAlgorithm);
        setParameterOrThrow(libraryPtr, new_instance, 53LL, hashAlg,
            "set_signature|set_parameter|Signature_HashAlgorithm");
    }

    // 5c) paramId=54 => algorithmVersion
    {
        CommandParameterStr<10244> ver(g_algorithmVersion);
        setParameterOrThrow(libraryPtr, new_instance, 54LL, ver,
            "set_signature|set_parameter|Signature_AlgorithmVersion");
    }

    // 5d) paramId=58 => base64 signature
    {
        CommandParameterStr<10244> b64(base64Signature.c_str());
        setParameterOrThrow(libraryPtr, new_instance, 58LL, b64,
            "set_signature|set_parameter|Signature_SignatureValue");
    }
    // 6) Return new_instance => success
    return new_instance;
}