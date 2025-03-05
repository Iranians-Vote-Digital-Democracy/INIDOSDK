#include <stdio.h>
#include <Windows.h>
#include <string>
#include <iostream>
#include "CardAuthentication.hpp"
#include "CardAuthResult.hpp"

bool dk_ShowFingerPrintUI = 0;
bool dk_ShowFaceInputUI = 0;
// Authentication methods:
// 0 = PIN
// 1 = ID PIN and FingerPrint PIN
// 2 = finger print UI
int  dk_AuthenticationMethod = 0; 
int  dk_FingerIndex1 = 2;
int  dk_FingerIndex2 = 1;
int  dk_fingerStatus1 = 3;
int  dk_fingerStatus2 = 3;


// Global function pointers
PFN_GET_NEW_INSTANCE pfn_get_new_instance;
PFN_FREE_INSTANCE    pfn_free_instance;
PFN_SET_PARAMETER    pfn_set_parameter;
PFN_GET_PARAMETER    pfn_get_parameter;
PFN_EXECUTE          pfn_execute;
PFN_FREE_LIBRARY     pfn_free_library;
PFN_LOAD_LIBRARY     pfn_load_library;

std::string dk_getCommandError(int a2) {
    if (a2 == 0)
        return "MDAS_SDK__NO_ERROR";
    else if (a2 == 1)
        return "MDAS_SDK_ERROR__PARAMETER_IS_NULL";
    else if (a2 == 2)
        return "MDAS_SDK_ERROR__COMMAND_NOT_FOUND";
    else if (a2 == 3)
        return "MDAS_SDK_ERROR__COMMAND_NOT_SUPPORTED";
    else
        return "Unknown Error";
}

void printError(std::string command, int32_t commandReturn) {
    std::cout << command + std::string("| error: ") + dk_getCommandError(commandReturn) << std::endl;
}


class DK_MDAS
{
private:
    HMODULE  m_module = nullptr;
    int64_t* m_library = nullptr;
    int64_t  m_windowLocInstance = 0;
    int64_t  m_windowSizeInstance = 0;
    int64_t  m_cardReaderInstance = 0;
    int64_t  m_uiOptionsInstance = 0;
    int64_t  m_backgroundColorInstance = 0;
    int64_t  m_initializeServiceInstance = 0;

public:
    DK_MDAS() {}
    ~DK_MDAS() {
        if (m_library) {
            if (m_windowLocInstance)
                pfn_free_instance(m_library, m_windowLocInstance);
            if (m_windowSizeInstance)
                pfn_free_instance(m_library, m_windowSizeInstance);
            printf("[+] About to free the library\n");
            pfn_free_library(m_library);
        }
        if (m_module)
            FreeLibrary(m_module);
    }

    bool load() {
        m_module = LoadLibraryA("dump_oep-modified_sec_fixedIAT.dll");
        if (!m_module) {
            printf("[-] Failed to load module. Error: %#.8x\n", GetLastError());
            return false;
        }

        // Get function addresses
        pfn_get_new_instance = (PFN_GET_NEW_INSTANCE)GetProcAddress(m_module, "get_new_instance");
        pfn_free_instance = (PFN_FREE_INSTANCE)GetProcAddress(m_module, "free_instance");
        pfn_set_parameter = (PFN_SET_PARAMETER)GetProcAddress(m_module, "set_parameter");
        pfn_get_parameter = (PFN_GET_PARAMETER)GetProcAddress(m_module, "get_parameter");
        pfn_execute = (PFN_EXECUTE)GetProcAddress(m_module, "execute");
        pfn_free_library = (PFN_FREE_LIBRARY)GetProcAddress(m_module, "free_library");
        pfn_load_library = (PFN_LOAD_LIBRARY)GetProcAddress(m_module, "load_library");

        // Verify all functions were found
        if (!pfn_get_new_instance || !pfn_free_instance || !pfn_set_parameter ||
            !pfn_get_parameter || !pfn_execute || !pfn_free_library || !pfn_load_library)
        {
            printf("[-] Failed to get one or more function addresses\n");
            return false;
        }
        return true;
    }

    void DisableATRCheck()
    {
        unsigned char patchData[] = { 0xE9, 0xEF, 0x00, 0x00, 0x00, 0x90 };
        unsigned char* targetAddress = (unsigned char*)0x18002F8F6;
        DWORD oldProtect;
        if (!VirtualProtect(targetAddress, sizeof(patchData), PAGE_EXECUTE_READWRITE, &oldProtect))
        {
            printf("Failed to change memory protection for ATR check | error = %#.8x\n", GetLastError());
            return;
        }

        memcpy(targetAddress, patchData, sizeof(patchData));

        DWORD temp;
        if (!VirtualProtect(targetAddress, sizeof(patchData), oldProtect, &temp))
        {
            printf("Failed to restore memory protection for ATR check | error = %#.8x\n", GetLastError());
            return;
        }
        printf("[+] Successfully disabled ATR check\n");
    }

    bool SetWindowOptions() {
        int windowLocation_X = 100;
        int windowLocation_Y = 100;
        m_windowLocInstance = pfn_get_new_instance(m_library, 410LL);
        int32_t commandReturn = pfn_set_parameter(m_library, m_windowLocInstance, 412LL, &windowLocation_X);
        if (commandReturn) {
            printError("set_window_location|set_parameter|WindowLocation_X", commandReturn);
            return false;
        }
        commandReturn = pfn_set_parameter(m_library, m_windowLocInstance, 413LL, &windowLocation_Y);
        if (commandReturn) {
            printError("set_window_location|set_parameter|WindowLocation_Y", commandReturn);
            return false;
        }

        int32_t windowSizeWidth = 50;
        int32_t windowSizeHeight = 50;
        m_windowSizeInstance = pfn_get_new_instance(m_library, 390LL);
        commandReturn = pfn_set_parameter(m_library, m_windowSizeInstance, 392LL, &windowSizeWidth);
        if (commandReturn) {
            printError("set_window_size|set_parameter|WindowSize_Width", commandReturn);
            return false;
        }
        commandReturn = pfn_set_parameter(m_library, m_windowSizeInstance, 393LL, &windowSizeHeight);
        if (commandReturn) {
            printError("set_window_size|set_parameter|WindowSize_Height", commandReturn);
            return false;
        }
        printf("[+] Window options are set\n");
        return true;
    }

    bool SetDeviceInfo() {
        CommandParameterStr<10244> cardReaderName("ACS ACR1252 1S CL Reader PICC 0"); 
        CommandParameterStr<10244> fingerScannerName("Unknown My Finger Scanner");
        CommandParameterStr<10244> cameraName("Unknown My Camera Name");
        m_cardReaderInstance = pfn_get_new_instance(m_library, 500LL);
        int32_t commandReturn = pfn_set_parameter(m_library, m_cardReaderInstance, 502LL, &cardReaderName);
        if (commandReturn) {
            printError("set_device_info|set_parameter|DeviceInfo_CardReaderName", commandReturn);
            return false;
        }
        commandReturn = pfn_set_parameter(m_library, m_cardReaderInstance, 503LL, &fingerScannerName);
        if (commandReturn) {
            printError("set_device_info|set_parameter|DeviceInfo_FingerScannerName", commandReturn);
            return false;
        }
        commandReturn = pfn_set_parameter(m_library, m_cardReaderInstance, 504LL, &cameraName);
        if (commandReturn) {
            printError("set_device_info|set_parameter|DeviceInfo_CameraName", commandReturn);
            return false;
        }
        printf("[+] Device Info Parameters are set\n");
        return true;
    }

    bool SetUIOptions() {
        m_uiOptionsInstance = pfn_get_new_instance(m_library, 430LL);
        if (!m_uiOptionsInstance) {
            printf("[-] Failed to create UI options instance\n");
            return false;
        }

        char showPinInputUI = 1; 
        int32_t commandReturn = pfn_set_parameter(m_library, m_uiOptionsInstance, 432LL, &showPinInputUI);
        if (commandReturn) {
            printError("set_ui_options|set_parameter|UiOptions_ShowPinInputUI", commandReturn);
            return false;
        } 
          
        commandReturn = pfn_set_parameter(m_library, m_uiOptionsInstance, 433LL, &dk_ShowFingerPrintUI);
        if (commandReturn) {
            printError("set_ui_options|set_parameter|UiOptions_ShowFingerPrintUI", commandReturn);
            return false;
        }

        char showFaceInputUI = 0;
        commandReturn = pfn_set_parameter(m_library, m_uiOptionsInstance, 434LL, &showFaceInputUI);
        if (commandReturn) {
            printError("set_ui_options|set_parameter|UiOptions_ShowFaceInputUI", commandReturn);
            return false;
        }

        m_backgroundColorInstance = pfn_get_new_instance(m_library, 440LL);
        commandReturn = pfn_set_parameter(m_library, m_uiOptionsInstance, 438LL, &m_backgroundColorInstance);
        if (commandReturn) {
            printError("set_ui_options|set_parameter|UiOptions_BackgroundColor", commandReturn);
            return false;
        }

        // Uncomment if you want to set a header image
        // char headerImagePath[10244] = { 0 };
        // strcpy_s(headerImagePath, sizeof(headerImagePath), "path/to/header/image.png");
        // commandReturn = pfn_set_parameter(m_library, m_uiOptionsInstance, 439LL, headerImagePath);
        // if (commandReturn)
        // {
        //     printError("set_ui_options|set_parameter|UiOptions_HeaderImage", commandReturn);
        //     return false;
        // }
        printf("[+] UI options are set\n");
        return true;
    }

    bool SetInitializeService() { 
        printf("[+] About to intialize service\n");
        // Create instance for InitializeServiceServer
        m_initializeServiceInstance = pfn_get_new_instance(m_library, 520LL);
        if (!m_initializeServiceInstance) {
            printf("[-] Failed to create initialize service instance\n");
            return false;
        }
        int32_t commandReturn = 0;
        CommandParameterStr<10244> serverAddress("127.0.0.1");//("127.0.0.1"); // nid1.bank-maskan.ir
        commandReturn = pfn_set_parameter(m_library, m_initializeServiceInstance, 523LL, &serverAddress);
        if (commandReturn) {
            printError("set_initialize_service|set_parameter|Initialize_v1_ServerAddress", commandReturn);
            return false;
        }

        //// Set service user credentials if required
        CommandParameterStr<10244> serverUserName("");
        commandReturn = pfn_set_parameter(m_library, m_initializeServiceInstance, 526LL, &serverUserName);
        if (commandReturn)
        {
            printError("set_initialize_service|set_parameter|Initialize_v1_ServerUserName", commandReturn);
            return false;
        }

        CommandParameterStr<10244> password("");
        commandReturn = pfn_set_parameter(m_library, m_initializeServiceInstance, 527LL, &password);
        if (commandReturn)
        {
            printError("set_initialize_service|set_parameter|Initialize_v1_ServerPassWord", commandReturn);
            return false;
        }

        // Set device info for the initialized service
        commandReturn = pfn_set_parameter(m_library, m_initializeServiceInstance, 522LL, (char*)m_cardReaderInstance);
        if (commandReturn) {
            printError("set_initialize_service|set_parameter|Initialize_v1_DeviceInfo", commandReturn);
            return false;
        }
        // Set UI options for the initialized service
        commandReturn = pfn_set_parameter(m_library, m_initializeServiceInstance, 524LL, (char*)m_uiOptionsInstance);
        if (commandReturn) {
            printError("set_initialize_service|set_parameter|Initialize_v1_UiOptions", commandReturn);
            return false;
        }
        // Free no-longer-needed instances
        pfn_free_instance(m_library, m_cardReaderInstance);
        pfn_free_instance(m_library, m_uiOptionsInstance);
        m_cardReaderInstance = 0;
        m_uiOptionsInstance = 0;

        return true;
    }

    // Builds a JSON-form string for the exception details
    std::string dk_getJsonFromException(int64_t exceptionInstance)
    {
        // Retrieve fields from the exception
        char category[10256] = { 0 };
        char cause[10256] = { 0 };
        char field[10256] = { 0 };
        int retryCount = 0;

        // Param ID 32 = Category
        int32_t commandReturn = pfn_get_parameter(m_library, exceptionInstance, 32LL, category);
        if (commandReturn) {
            printError("create_json_form_result_exception|get_parameter|ResultException_Category", commandReturn);
            return std::string();
        }

        // Param ID 33 = Cause
        commandReturn = pfn_get_parameter(m_library, exceptionInstance, 33LL, cause);
        if (commandReturn) {
            printError("create_json_form_result_exception|get_parameter|ResultException_Cause", commandReturn);
            return std::string();
        }
        // Param ID 34 = Field
        commandReturn = pfn_get_parameter(m_library, exceptionInstance, 34LL, field);
        if (commandReturn) {
            printError("create_json_form_result_exception|get_parameter|ResultException_Field", commandReturn);
            return std::string();
        };
        // Param ID 35 = RetryCount
        commandReturn = pfn_get_parameter(m_library, exceptionInstance, 35LL, &retryCount);
        if (commandReturn) {
            printError("create_json_form_result_exception|get_parameter|ResultException_RetryCount", commandReturn);
            return std::string();
        }

        // Build the JSON
        std::string json = "{";
        json += "\"category\":\"" + std::string(category) + "\",";
        json += "\"cause\":\"" + std::string(cause) + "\",";
        json += "\"field\":\"" + std::string(field) + "\",";
        json += "\"retryCount\":" + std::to_string(retryCount);
        json += "}";

        return json;
    }

    // Parse any exception details for "Initialize_v1_Result"
    bool GetResultException(int64_t exceptionInstance) {
        // We can gather data or build a JSON from it
        std::string exceptionJson = dk_getJsonFromException(exceptionInstance);
        if (exceptionJson.empty()) {
            printf("exceptionJson is empty\n");
            // Error was already printed
            return false;
        }

        // Print the JSON so we can see the details
        std::cout << "[!] Result Exception JSON: " << exceptionJson << std::endl;
        return true;
    }

    // Check if "Initialize_v1_Result" indicates success or exception
    bool getInitializeV1Result()
    {
        // Create an instance to hold "Initialize_v1_InitializeResult" (param ID 540)
        int64_t newInstance = pfn_get_new_instance(m_library, 540LL);
        if (!newInstance) {
            printError("print_initialize_result|new_instance|Initialize_v1_InitializeResult", 1);
            return false;
        }

        // Retrieve Initialize_v1_InitializeResult (param ID 525)
        int32_t commandReturn = pfn_get_parameter(m_library, m_initializeServiceInstance, 525LL, (char*)newInstance);
        if (commandReturn) {
            printError("print_initialize_result|get_parameter|Initialize_v1_InitializeResult", commandReturn);
            pfn_free_instance(m_library, newInstance);
            return false;
        }

        // Retrieve "ResultType" (param ID 542)
        int resultType = 0;
        commandReturn = pfn_get_parameter(m_library, newInstance, 542LL, &resultType);
        if (commandReturn) {
            printError("print_initialize_result|get_parameter|InitializeResult_ResultType", commandReturn);
            pfn_free_instance(m_library, newInstance);
            return false;
        }

        if (resultType == 1) {
            // There's an exception => param ID 543
            int64_t resultExceptionInstance = pfn_get_new_instance(m_library, 30LL);
            if (!resultExceptionInstance) {
                printError("print_initialize_result|new_instance|InitializeResult_ResultException", 1);
                pfn_free_instance(m_library, newInstance);
                return false;
            }
            commandReturn = pfn_get_parameter(m_library, newInstance, 543LL, (char*)resultExceptionInstance);
            if (commandReturn) {
                printError("print_initialize_result|get_parameter|InitializeResult_ResultException", commandReturn);
                pfn_free_instance(m_library, resultExceptionInstance);
                pfn_free_instance(m_library, newInstance);
                return false;
            }
            // Retrieve the exception details
            GetResultException(resultExceptionInstance);

            pfn_free_instance(m_library, resultExceptionInstance);
            pfn_free_instance(m_library, newInstance);

            // According to the IDA snippet, returning 0 means error
            return false;
        }
        printf("[+] getInitializeV1Result successful\n");
        // If resultType != 1 => success
        pfn_free_instance(m_library, newInstance);
        return true;
    }


    bool GetMocFinger1And2Index(int64_t* mdasLibrary)
    {
        // Create a new instance with parameter 610
        int64_t mocFingerIndexInstance = pfn_get_new_instance(mdasLibrary, 610LL);
        if (!mocFingerIndexInstance)
        {
            printError("get_moc_finger_index_service|new_instance|GetMocFingerIndex_v1", 1);
            return false;
        }

        // Execute: get_moc_finger_index_service
        int32_t commandReturn = pfn_execute(mdasLibrary, mocFingerIndexInstance);
        if (commandReturn)
        {
            printError("get_moc_finger_index_service|execute|GetMocFingerIndex_v1", commandReturn);
            pfn_free_instance(mdasLibrary, mocFingerIndexInstance);
            return false;
        }

        // Create a new instance for the FingerIndexResult (param 560)
        int64_t fingerIndexResultInstance = pfn_get_new_instance(mdasLibrary, 560LL);
        if (!fingerIndexResultInstance)
        {
            printError("get_moc_finger_index_service|new_instance|FingerIndexResult", 1);
            pfn_free_instance(mdasLibrary, mocFingerIndexInstance);
            return false;
        }

        // Get parameter 612: FingerIndexResult
        commandReturn = pfn_get_parameter(mdasLibrary, mocFingerIndexInstance, 612LL, (char*)fingerIndexResultInstance);
        if (commandReturn)
        {
            printError("get_moc_finger_index_service|get_parameter|GetMocFingerIndex_v1_FingerIndexResult", commandReturn);
            pfn_free_instance(mdasLibrary, fingerIndexResultInstance);
            pfn_free_instance(mdasLibrary, mocFingerIndexInstance);
            return false;
        }

        // Retrieve Finger_1 (param 563)
        int32_t fingerIndex1 = 0;
        commandReturn = pfn_get_parameter(mdasLibrary, fingerIndexResultInstance, 563LL, &fingerIndex1);
        if (commandReturn)
        {
            printError("get_moc_finger_index_service|get_parameter|FingerIndexResult_Finger_1", commandReturn);
            pfn_free_instance(mdasLibrary, fingerIndexResultInstance);
            pfn_free_instance(mdasLibrary, mocFingerIndexInstance);
            return false;
        }

        // Retrieve FingerStatus_1 (param 564)
        int32_t fingerStatus1 = 0;
        commandReturn = pfn_get_parameter(mdasLibrary, fingerIndexResultInstance, 564LL, &fingerStatus1);
        if (commandReturn)
        {
            printError("get_moc_finger_index_service|get_parameter|FingerIndexResult_FingerStatus_1", commandReturn);
            pfn_free_instance(mdasLibrary, fingerIndexResultInstance);
            pfn_free_instance(mdasLibrary, mocFingerIndexInstance);
            return false;
        }
         
        // Retrieve Finger_2 (param 565)
        int32_t fingerIndex2 = 0;
        commandReturn = pfn_get_parameter(mdasLibrary, fingerIndexResultInstance, 565LL, &fingerIndex2);
        if (commandReturn)
        {
            printError("get_moc_finger_index_service|get_parameter|FingerIndexResult_Finger_2", commandReturn);
            pfn_free_instance(mdasLibrary, fingerIndexResultInstance);
            pfn_free_instance(mdasLibrary, mocFingerIndexInstance);
            return false;
        }

        // Retrieve FingerStatus_2 (param 566)
        int32_t fingerStatus2 = 0;
        commandReturn = pfn_get_parameter(mdasLibrary, fingerIndexResultInstance, 566LL, &fingerStatus2);
        if (commandReturn)
        {
            printError("get_moc_finger_index_service|get_parameter|FingerIndexResult_FingerStatus_2", commandReturn);
            pfn_free_instance(mdasLibrary, fingerIndexResultInstance);
            pfn_free_instance(mdasLibrary, mocFingerIndexInstance);
            return false;
        }

        // Clean up
        pfn_free_instance(mdasLibrary, fingerIndexResultInstance);
        pfn_free_instance(mdasLibrary, mocFingerIndexInstance);

        // Log results if needed
        printf("[+] Finger1Index = %d, FingerStatus1 = %d\n", fingerIndex1, fingerStatus1);
        printf("[+] Finger2Index = %d, FingerStatus2 = %d\n", fingerIndex2, fingerStatus2);
        return true;
    }

    bool InitializeServiceV1()
    {
        printf("[+] About to execute intialize v1\n");
        // Executes "InitializeServiceServer" (param ID 520 was used in SetInitializeService)
        int32_t commandReturn = pfn_execute(m_library, m_initializeServiceInstance);
        if (commandReturn)
        {
            printError("initialize_service|execute|Initialize_v1", commandReturn);
            return false;
        }
        printf("[+] About to call getInitializeV1Result\n");
        // Now check if there's an exception or success
        bool result = getInitializeV1Result();
        // IDA returns "0" on success, "204" on error
        // We'll convert that to bool

        return result;
    }

    bool run() 
    {
        m_library = pfn_load_library();
        if (m_library) {
            printf("press any key to start\n");
            getchar(); 
            // If the load fails, we do the following calls anyway:
            if (!SetDeviceInfo()) return false;
            if (!SetWindowOptions()) return false;
            if (!SetUIOptions()) return false;
            if (!SetInitializeService()) return false;
            InitializeServiceV1();
           // if (!InitializeServiceV1()) return false;

           // SetCurrentDirectoryW(L"C:\\Program Files (x86)\\PKI\\Dastine\\NId\\v6");

           
          /*  printf("[+] About to call GetMocFinger1And2Index\n"); 
            printf("[+] Press any key to continue\n");
            getchar();
            GetMocFinger1And2Index(m_library);*/


            // -------------------------------------------------------
            // Now, after we have finger indexes, do CardAuthentication
            // -------------------------------------------------------
       
            CardAuthentication cardAuth;
            size_t Nonce;
            bool ok = cardAuth.CardAuthenticate(0, (char*)m_library);
            if (!ok)
            {
                printf("[-] CardAuthenticate failed\n");
                // handle error, or just return false
                return false;
            }
            else
            { 
               
                printf("[+] CardAuthenticate succeeded\n");

                CardAuthResult cardAuthResult;
                std::string result = cardAuthResult.getCardAuthenticationResult((char*)m_library, cardAuth.m_authV1Instance);
                printf("Card Auth result:\n %s\n", result.c_str());
            }

            if (cardAuth.m_authV1Instance) {
                pfn_free_instance(m_library, cardAuth.m_authV1Instance);
            }
    
            if (m_initializeServiceInstance) {
                pfn_free_instance(m_library, m_initializeServiceInstance);
                m_initializeServiceInstance = 0;
            }

        }
        return true;
    }
};


int main()
{
    DK_MDAS dk_mdas;
    if (dk_mdas.load()) {
        dk_mdas.DisableATRCheck();
        dk_mdas.run();
    }
    return 0;
}
