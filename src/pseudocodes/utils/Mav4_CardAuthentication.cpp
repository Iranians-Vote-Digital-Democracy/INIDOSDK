#include <string>
#include <unordered_map>
#include <vector>
#include <memory>
#include <cstdint>
#include <cstring>
#include <iostream>

// Forward declarations
class CardLibBase;
class MAV4_MDAS_1;

// Helper structures and classes
struct StrObj {
    std::string buffer;
};

class RuntimeError {
public:
    void operator_equal(const char* message) {
        errorMessage = message;
    }
    
private:
    std::string errorMessage;
};

// Utility functions
std::string* Clh_StringToLower(std::string* result, const std::string* input);
std::string* Clh_TripleDesEncrypt(std::string* result, void* context, int line, std::string* plaintext, std::string* key, std::string* mode);
std::string* Clh_TripleDesDecrypt(std::string* result, std::string* key, std::string* mode);
std::string* Clh_DesEncrypt(std::string* result, std::string* key, std::string* mode);
std::string* Clh_DesDecrypt(std::string* result, std::string* context, std::string* mode);
std::string* Clh_Truncate(std::string* result, void* context, int line, std::string* input, std::string* offset, std::string* length);
std::string* Clh_Add(std::string* result, void* context, int64_t line, std::string* a, std::string* b, std::string* base);
std::string* Clh_Sub(std::string* result, std::string* a, std::string* b);
std::string* Clh_XOR(std::string* result, std::string* data);
std::string* Clh_SHA1(std::string* result);
std::string* Clh_SHA256(std::string* result);
std::string* Clh_GetLength(std::string* result, std::string* base);
std::string* Clh_AddPadding(std::string* result, void* context, int64_t line, std::string* padType, std::string* data);
std::string* Clh_AddLen(std::string* result, std::string* data, std::string* mode);
std::string* Clh_Hex2Dec(std::string* result, void* context, int64_t line, std::string* hex);

// CardLibBase class to handle APDU commands
class CardLibBase {
public:
    static std::string* sendAPDU(void* context, std::string* result, std::string* command, int line, StrObj** options = nullptr);
};

// Main MAV4_MDAS_1 class
class MAV4_MDAS_1 {
private:
    std::unordered_map<std::string, std::string> dataMap;
    RuntimeError runtimeError;
    char data[1272];
    std::string lastCommand;
    
    std::string* GetOrInsertHashTableEntry(std::string* key) {
        // If the key doesn't exist, it will be created with empty string
        return &dataMap[*key];
    }

public:
    int64_t MDAS_CardAuthentication(
        std::string* result,
        std::string* idpin_ascii,
        std::string* iasenckey,
        std::string* iasmackey,
        std::string* terminal_data,
        std::string* trnd,
        std::string* kifd,
        std::string** signeddata,
        std::string** status,
        std::string** returncode)
    {
        // Set authentication state
        *reinterpret_cast<int*>(data + 1272) = 1;
        
        // Set current function name
        lastCommand = "MDAS_CardAuthentication";
        
        // Initialize local variables
        std::string idpinKey = "@idpin_ascii";
        std::string srcStr;
        
        // Copy input parameters to session variables
        srcStr = *idpin_ascii;
        std::string* loweredStr = Clh_StringToLower(new std::string(), &srcStr);
        std::string* destination = GetOrInsertHashTableEntry(&idpinKey);
        *destination = *loweredStr;
        delete loweredStr;
        
        std::string iasencKey = "@iasenckey";
        std::string tempIasenckey = *iasenckey;
        loweredStr = Clh_StringToLower(new std::string(), &tempIasenckey);
        destination = GetOrInsertHashTableEntry(&iasencKey);
        *destination = *loweredStr;
        delete loweredStr;
        
        std::string iasmackeyKey = "@iasmackey";
        std::string tempIasmackey = *iasmackey;
        loweredStr = Clh_StringToLower(new std::string(), &tempIasmackey);
        destination = GetOrInsertHashTableEntry(&iasmackeyKey);
        *destination = *loweredStr;
        delete loweredStr;
        
        std::string terminalDataKey = "@terminal_data";
        std::string tempTerminalData = *terminal_data;
        loweredStr = Clh_StringToLower(new std::string(), &tempTerminalData);
        destination = GetOrInsertHashTableEntry(&terminalDataKey);
        *destination = *loweredStr;
        delete loweredStr;
        
        std::string trndKey = "@trnd";
        std::string tempTrnd = *trnd;
        loweredStr = Clh_StringToLower(new std::string(), &tempTrnd);
        destination = GetOrInsertHashTableEntry(&trndKey);
        *destination = *loweredStr;
        delete loweredStr;
        
        std::string kifdKey = "@kifd";
        std::string tempKifd = *kifd;
        loweredStr = Clh_StringToLower(new std::string(), &tempKifd);
        destination = GetOrInsertHashTableEntry(&kifdKey);
        *destination = *loweredStr;
        delete loweredStr;
        
        // Initialize return code and status
        std::string retcodeKey = "%returncode";
        destination = GetOrInsertHashTableEntry(&retcodeKey);
        *destination = "ff";
        
        std::string signeddataKey = "%signeddata";
        destination = GetOrInsertHashTableEntry(&signeddataKey);
        *destination = "";
        
        std::string statusKey = "%status";
        destination = GetOrInsertHashTableEntry(&statusKey);
        *destination = "f3";
        
        std::string keyidKey = "%keyid";
        destination = GetOrInsertHashTableEntry(&keyidKey);
        *destination = "03";
        
        std::string pinidKey = "%pinid";
        destination = GetOrInsertHashTableEntry(&pinidKey);
        *destination = "01";
        
        std::string algoidKey = "%algoid";
        destination = GetOrInsertHashTableEntry(&algoidKey);
        *destination = "02";
        
        // === Start card authentication process ===
        
        // Select application
        std::string selectCmd = "00a4040008a000000018434d00";
        std::string response;
        CardLibBase::sendAPDU(this, &response, &selectCmd, 17);
        
        // Get CPLC data
        std::string cplcCmd = "80ca9f7f2d";
        std::string cplcKey = "%cplc";
        std::string* cplcData = CardLibBase::sendAPDU(this, new std::string(), &cplcCmd, 19);
        destination = GetOrInsertHashTableEntry(&cplcKey);
        *destination = *cplcData;
        delete cplcData;
        
        // Extract serial number from CPLC
        std::string lengthStr = "08";
        std::string offsetStr = "13";
        std::string cplcKeyForLookup = "%cplc";
        std::string snKey = "%sn.icc";
        
        std::string* cplcDataForTruncate = GetOrInsertHashTableEntry(&cplcKeyForLookup);
        std::string tempStr;
        tempStr = *cplcDataForTruncate;
        
        std::string* truncated = Clh_Truncate(new std::string(), this->data + 104, 20, &tempStr, &offsetStr, &lengthStr);
        destination = GetOrInsertHashTableEntry(&snKey);
        *destination = *truncated;
        delete truncated;
        
        // Select card manager
        std::string selectCMCmd = "00a404000ca0000000180c000001634200";
        StrObj* allOptions = new StrObj();
        allOptions->buffer = "all";
        std::string cardManagerResponse;
        CardLibBase::sendAPDU(this, &cardManagerResponse, &selectCMCmd, 23, &allOptions);
        
        // Save last result and SW
        std::string lastResultKey = "%lastresult";
        std::string swKey = "%sw";
        std::string* lastResult = GetOrInsertHashTableEntry(&lastResultKey);
        destination = GetOrInsertHashTableEntry(&swKey);
        *destination = *lastResult;
        
        // Select MF
        std::string selectMFCmd = "00a40000023f00";
        std::string selectMFResponse;
        CardLibBase::sendAPDU(this, &selectMFResponse, &selectMFCmd, 26);
        
        // Copy PIN to session
        std::string idpinKeyLookup = "@idpin_ascii";
        std::string idpinSessionKey = "%idpin_ascii";
        std::string* idpinValue = GetOrInsertHashTableEntry(&idpinKeyLookup);
        destination = GetOrInsertHashTableEntry(&idpinSessionKey);
        *destination = *idpinValue;
        
        // Ensure PIN has correct length
        while (true) {
            std::string hexBase = "h";
            std::string pinLenKey = "%len";
            std::string* lenValue = Clh_GetLength(new std::string(), &hexBase);
            destination = GetOrInsertHashTableEntry(&pinLenKey);
            *destination = *lenValue;
            delete lenValue;
            
            bool correctLength = (*GetOrInsertHashTableEntry(&pinLenKey) == "10");
            if (correctLength) break;
            
            // Pad PIN if needed
            std::string* pinValue = GetOrInsertHashTableEntry(&idpinSessionKey);
            std::string* paddedPin = new std::string(*pinValue + "00");
            destination = GetOrInsertHashTableEntry(&idpinSessionKey);
            *destination = *paddedPin;
            delete paddedPin;
        }
        
        // Verify PIN
        std::string pinidValue = *GetOrInsertHashTableEntry(&pinidKey);
        std::string verifyPinCmd = "002000" + pinidValue + "10";
        std::string* pinValue = GetOrInsertHashTableEntry(&idpinSessionKey);
        verifyPinCmd += *pinValue;
        
        allOptions = new StrObj();
        allOptions->buffer = "all";
        std::string verifyPinResponse;
        CardLibBase::sendAPDU(this, &verifyPinResponse, &verifyPinCmd, 40, &allOptions);
        
        // Check PIN verification result
        std::string* swValue = GetOrInsertHashTableEntry(&swKey);
        
        if (*swValue == "9000") {
            // PIN verification successful
            std::string* statusValue = GetOrInsertHashTableEntry(&statusKey);
            *statusValue = "11";
            
            // MSE SET command
            std::string mseSetCmd = "002241a406830101950180";
            std::string mseSetResponse;
            CardLibBase::sendAPDU(this, &mseSetResponse, &mseSetCmd, 66);
            
            // Set IFD serial number
            std::string snIfdKey = "%sn.ifd";
            destination = GetOrInsertHashTableEntry(&snIfdKey);
            *destination = "aabbccdd44668877";
            
            // Get challenge (random number from card)
            std::string getChallengeCmd = "8084000008";
            std::string crndKey = "%crnd";
            std::string* crndValue = CardLibBase::sendAPDU(this, new std::string(), &getChallengeCmd, 70);
            destination = GetOrInsertHashTableEntry(&crndKey);
            *destination = *crndValue;
            delete crndValue;
            
            // Create session key derivation data
            std::string kifdKeyLookup = "@kifd";
            std::string snIccKey = "%sn.icc";
            std::string crndKeyLookup = "%crnd";
            std::string snIfdKeyLookup = "%sn.ifd";
            std::string trndKeyLookup = "@trnd";
            std::string sessionDataKey = "%s";
            
            std::string sessionData = 
                *GetOrInsertHashTableEntry(&trndKeyLookup) +
                *GetOrInsertHashTableEntry(&snIfdKeyLookup) +
                *GetOrInsertHashTableEntry(&crndKeyLookup) +
                *GetOrInsertHashTableEntry(&snIccKey) +
                *GetOrInsertHashTableEntry(&kifdKeyLookup);
                
            destination = GetOrInsertHashTableEntry(&sessionDataKey);
            *destination = sessionData;
            
            // Encrypt session data
            std::string mode = "cbc";
            std::string sessionKey = "%s";
            std::string iasencKeyLookup = "@iasenckey";
            std::string encryptedDataKey = "%s'";
            
            std::string* sessionValue = GetOrInsertHashTableEntry(&sessionKey);
            std::string* iasencValue = GetOrInsertHashTableEntry(&iasencKeyLookup);
            std::string* encryptedValue = Clh_TripleDesEncrypt(new std::string(), this->data + 104, 74, sessionValue, iasencValue, &mode);
            
            destination = GetOrInsertHashTableEntry(&encryptedDataKey);
            *destination = *encryptedValue;
            delete encryptedValue;
            
            // Initialize SSC (Send Sequence Counter)
            std::string sscKey = "%ssc";
            destination = GetOrInsertHashTableEntry(&sscKey);
            *destination = "0000000000000000";
            
            // Create MAC calculation data
            std::string encryptedDataLookup = "%s'";
            std::string sscKeyLookup = "%ssc";
            std::string xxKey = "%xx";
            
            std::string xxData = *GetOrInsertHashTableEntry(&sscKeyLookup) + 
                            *GetOrInsertHashTableEntry(&encryptedDataLookup);
                            
            destination = GetOrInsertHashTableEntry(&xxKey);
            *destination = xxData;
            
            // Calculate MAC key for left part
            std::string lengthForTruncate = "08";
            std::string offsetForTruncate = "00";
            std::string iasmacKeyLookup = "@iasmackey";
            std::string iasmacLKey = "%iasmac_l";
            
            std::string* iasmacValue = GetOrInsertHashTableEntry(&iasmacKeyLookup);
            std::string tempIasmacValue = *iasmacValue;
            
            std::string* truncatedForMacL = Clh_Truncate(new std::string(), this->data + 104, 77, &tempIasmacValue, &offsetForTruncate, &lengthForTruncate);
            destination = GetOrInsertHashTableEntry(&iasmacLKey);
            *destination = *truncatedForMacL;
            delete truncatedForMacL;
            
            // Encrypt xx with MAC key (L)
            std::string modeForDes = "cbc";
            std::string iasmacLKeyLookup = "%iasmac_l";
            std::string xxKeyLookup = "%xx";
            std::string yyKey = "%yy";
            
            std::string* iasmacLValue = GetOrInsertHashTableEntry(&iasmacLKeyLookup);
            std::string* encryptedYyValue = Clh_DesEncrypt(new std::string(), iasmacLValue, &modeForDes);
            
            destination = GetOrInsertHashTableEntry(&yyKey);
            *destination = *encryptedYyValue;
            delete encryptedYyValue;
            
            // Truncate YY value
            std::string lengthForYy = "08";
            std::string offsetForYy = "64";
            std::string yyKeyLookup = "%yy";
            std::string yy1Key = "%yy1";
            
            std::string* yyValue = GetOrInsertHashTableEntry(&yyKeyLookup);
            std::string tempYyValue = *yyValue;
            
            std::string* truncatedForYy1 = Clh_Truncate(new std::string(), this->data + 104, 79, &tempYyValue, &offsetForYy, &lengthForYy);
            destination = GetOrInsertHashTableEntry(&yy1Key);
            *destination = *truncatedForYy1;
            delete truncatedForYy1;
            
            // XOR YY1 with constant
            std::string yy1KeyLookup = "%yy1";
            std::string xorKey = "%x0r";
            std::string* constantForXor = new std::string("8000000000000000");
            
            std::string* yy1Value = GetOrInsertHashTableEntry(&yy1KeyLookup);
            std::string tempYy1Value = *yy1Value;
            
            std::string* xoredValue = Clh_XOR(new std::string(), constantForXor);
            destination = GetOrInsertHashTableEntry(&xorKey);
            *destination = *xoredValue;
            delete xoredValue;
            delete constantForXor;
            
            // Calculate MAC with Triple DES
            std::string modeForTDes = "ecb";
            std::string iasmacKeyForMac = "@iasmackey";
            std::string xorKeyLookup = "%x0r";
            std::string macKey = "%mac";
            
            std::string* iasmacValueForMac = GetOrInsertHashTableEntry(&iasmacKeyForMac);
            std::string* xorValue = GetOrInsertHashTableEntry(&xorKeyLookup);
            
            std::string* macValue = Clh_TripleDesEncrypt(new std::string(), this->data + 104, 81, xorValue, iasmacValueForMac, &modeForTDes);
            destination = GetOrInsertHashTableEntry(&macKey);
            *destination = *macValue;
            delete macValue;
            
            // Send external authenticate command
            std::string encryptedDataForAuth = "%s'";
            std::string macKeyLookup = "%mac";
            std::string maResKey = "%ma-res";
            
            std::string authenticateCmd = "8082000048" + 
                                        *GetOrInsertHashTableEntry(&encryptedDataForAuth) + 
                                        *GetOrInsertHashTableEntry(&macKeyLookup) + 
                                        "48";
            
            allOptions = new StrObj();
            allOptions->buffer = "all";
            std::string* authResponse = CardLibBase::sendAPDU(this, new std::string(), &authenticateCmd, 84, &allOptions);
            
            destination = GetOrInsertHashTableEntry(&maResKey);
            *destination = *authResponse;
            delete authResponse;
            
            // Extract TRND (Terminal random)
            std::string lengthForTrnd = "04";
            std::string offsetForTrnd = "04";
            std::string trndKeyForExtract = "@trnd";
            std::string trnd4Key = "%trnd_4";
            
            std::string* trndValue = GetOrInsertHashTableEntry(&trndKeyForExtract);
            std::string tempTrndValue = *trndValue;
            
            std::string* truncatedTrnd = Clh_Truncate(new std::string(), this->data + 104, 88, &tempTrndValue, &offsetForTrnd, &lengthForTrnd);
            destination = GetOrInsertHashTableEntry(&trnd4Key);
            *destination = *truncatedTrnd;
            delete truncatedTrnd;
            
            // Extract CRND (Card random)
            std::string lengthForCrnd = "04";
            std::string offsetForCrnd = "04";
            std::string crndKeyForExtract = "%crnd";
            std::string crnd4Key = "%crnd_4";
            
            std::string* crndValue = GetOrInsertHashTableEntry(&crndKeyForExtract);
            std::string tempCrndValue = *crndValue;
            
            std::string* truncatedCrnd = Clh_Truncate(new std::string(), this->data + 104, 89, &tempCrndValue, &offsetForCrnd, &lengthForCrnd);
            destination = GetOrInsertHashTableEntry(&crnd4Key);
            *destination = *truncatedCrnd;
            delete truncatedCrnd;
            
            // Update SSC with randomness
            std::string trnd4KeyLookup = "%trnd_4";
            std::string crnd4KeyLookup = "%crnd_4";
            std::string sscUpdateKey = "%ssc";
            
            std::string sscUpdate = *GetOrInsertHashTableEntry(&crnd4KeyLookup) + 
                                *GetOrInsertHashTableEntry(&trnd4KeyLookup);
                                
            destination = GetOrInsertHashTableEntry(&sscUpdateKey);
            *destination = sscUpdate;
            
            // Extract encrypted data from authentication response
            std::string lengthForSs = "64";
            std::string offsetForSs = "00";
            std::string maResKeyLookup = "%ma-res";
            std::string ssPrimeKey = "%ss'";
            
            std::string* maResValue = GetOrInsertHashTableEntry(&maResKeyLookup);
            std::string tempMaResValue = *maResValue;
            
            std::string* truncatedForSs = Clh_Truncate(new std::string(), this->data + 104, 92, &tempMaResValue, &offsetForSs, &lengthForSs);
            destination = GetOrInsertHashTableEntry(&ssPrimeKey);
            *destination = *truncatedForSs;
            delete truncatedForSs;
            
            // Extract MAC from authentication response
            std::string lengthForMac = "08";
            std::string offsetForMac = "64";
            std::string maResKeyForMac = "%ma-res";
            std::string iccMacKey = "%icc.mac";
            
            std::string* maResValueForMac = GetOrInsertHashTableEntry(&maResKeyForMac);
            std::string tempMaResValueForMac = *maResValueForMac;
            
            std::string* truncatedForMac = Clh_Truncate(new std::string(), this->data + 104, 93, &tempMaResValueForMac, &offsetForMac, &lengthForMac);
            destination = GetOrInsertHashTableEntry(&iccMacKey);
            *destination = *truncatedForMac;
            delete truncatedForMac;
            
            // Decrypt SS'
            std::string modeForDecrypt = "cbc";
            std::string iasencKeyForDecrypt = "@iasenckey";
            std::string ssPrimeKeyLookup = "%ss'";
            std::string ssKey = "%ss";
            
            std::string* iasencValueForDecrypt = GetOrInsertHashTableEntry(&iasencKeyForDecrypt);
            std::string* decryptedSsValue = Clh_TripleDesDecrypt(new std::string(), iasencValueForDecrypt, &modeForDecrypt);
            
            destination = GetOrInsertHashTableEntry(&ssKey);
            *destination = *decryptedSsValue;
            delete decryptedSsValue;
            
            // Extract ICC key
            std::string lengthForKicc = "32";
            std::string offsetForKicc = "32";
            std::string ssKeyLookup = "%ss";
            std::string kiccKey = "%kicc";
            
            std::string* ssValue = GetOrInsertHashTableEntry(&ssKeyLookup);
            std::string tempSsValue = *ssValue;
            
            std::string* truncatedForKicc = Clh_Truncate(new std::string(), this->data + 104, 96, &tempSsValue, &offsetForKicc, &lengthForKicc);
            destination = GetOrInsertHashTableEntry(&kiccKey);
            *destination = *truncatedForKicc;
            delete truncatedForKicc;
            
            // Calculate session key
            std::string kiccKeyLookup = "%kicc";
            std::string kifdKeyForSession = "@kifd";
            std::string kIfdIccKey = "%k.ifd_icc";
            
            std::string* kiccValue = GetOrInsertHashTableEntry(&kiccKeyLookup);
            std::string tempKiccValue = *kiccValue;
            
            std::string* kifdValueForSession = GetOrInsertHashTableEntry(&kifdKeyForSession);
            std::string tempKifdValueForSession = *kifdValueForSession;
            
            std::string* xoredIfdIcc = Clh_XOR(new std::string(), &tempKiccValue);
            destination = GetOrInsertHashTableEntry(&kIfdIccKey);
            *destination = *xoredIfdIcc;
            delete xoredIfdIcc;
            
            // Calculate encryption key hash
            std::string kIfdIccKeyLookup = "%k.ifd_icc";
            std::string skencHashKey = "%skenc_hash";
            
            std::string* kIfdIccValue = GetOrInsertHashTableEntry(&kIfdIccKeyLookup);
            std::string hashInput = *kIfdIccValue + "00000001";
            
            std::string* hashValue = Clh_SHA1(new std::string());
            destination = GetOrInsertHashTableEntry(&skencHashKey);
            *destination = *hashValue;
            delete hashValue;
            
            // Extract encryption key
            std::string lengthForSkenc = "16";
            std::string offsetForSkenc = "00";
            std::string skencHashKeyLookup = "%skenc_hash";
            std::string skencKey = "%skenc";
            
            std::string* skencHashValue = GetOrInsertHashTableEntry(&skencHashKeyLookup);
            std::string tempSkencHashValue = *skencHashValue;
            
            std::string* truncatedForSkenc = Clh_Truncate(new std::string(), this->data + 104, 99, &tempSkencHashValue, &offsetForSkenc, &lengthForSkenc);
            destination = GetOrInsertHashTableEntry(&skencKey);
            *destination = *truncatedForSkenc;
            delete truncatedForSkenc;
            
            // Extract left part of encryption key
            std::string lengthForSkencL = "08";
            std::string offsetForSkencL = "00";
            std::string skencKeyLookup = "%skenc";
            std::string skencLKey = "%skenc_l";
            
            std::string* skencValue = GetOrInsertHashTableEntry(&skencKeyLookup);
            std::string tempSkencValue = *skencValue;
            
            std::string* truncatedForSkencL = Clh_Truncate(new std::string(), this->data + 104, 100, &tempSkencValue, &offsetForSkencL, &lengthForSkencL);
            destination = GetOrInsertHashTableEntry(&skencLKey);
            *destination = *truncatedForSkencL;
            delete truncatedForSkencL;
            
            // Extract right part of encryption key
            std::string lengthForSkencR = "08";
            std::string offsetForSkencR = "08";
            std::string skencKeyForR = "%skenc";
            std::string skencRKey = "%skenc_r";
            
            std::string* skencValueForR = GetOrInsertHashTableEntry(&skencKeyForR);
            std::string tempSkencValueForR = *skencValueForR;
            
            std::string* truncatedForSkencR = Clh_Truncate(new std::string(), this->data + 104, 101, &tempSkencValueForR, &offsetForSkencR, &lengthForSkencR);
            destination = GetOrInsertHashTableEntry(&skencRKey);
            *destination = *truncatedForSkencR;
            delete truncatedForSkencR;
            
            // Calculate MAC key hash
            std::string kIfdIccKeyForMac = "%k.ifd_icc";
            std::string skmacHashKey = "%skmac_hash";
            
            std::string* kIfdIccValueForMac = GetOrInsertHashTableEntry(&kIfdIccKeyForMac);
            std::string hashInputForMac = *kIfdIccValueForMac + "00000002";
            
            std::string* hashValueForMac = Clh_SHA1(new std::string());
            destination = GetOrInsertHashTableEntry(&skmacHashKey);
            *destination = *hashValueForMac;
            delete hashValueForMac;
            
            // Extract MAC key
            std::string lengthForSkmac = "16";
            std::string offsetForSkmac = "00";
            std::string skmacHashKeyLookup = "%skmac_hash";
            std::string skmacKey = "%skmac";
            
            std::string* skmacHashValue = GetOrInsertHashTableEntry(&skmacHashKeyLookup);
            std::string tempSkmacHashValue = *skmacHashValue;
            
            std::string* truncatedForSkmac = Clh_Truncate(new std::string(), this->data + 104, 103, &tempSkmacHashValue, &offsetForSkmac, &lengthForSkmac);
            destination = GetOrInsertHashTableEntry(&skmacKey);
            *destination = *truncatedForSkmac;
            delete truncatedForSkmac;
            
            // Extract left part of MAC key
            std::string lengthForSkmacL = "08";
            std::string offsetForSkmacL = "00";
            std::string skmacKeyLookup = "%skmac";
            std::string skmacLKey = "%skmac_l";
            
            std::string* skmacValue = GetOrInsertHashTableEntry(&skmacKeyLookup);
            std::string tempSkmacValue = *skmacValue;
            
            std::string* truncatedForSkmacL = Clh_Truncate(new std::string(), this->data + 104, 104, &tempSkmacValue, &offsetForSkmacL, &lengthForSkmacL);
            destination = GetOrInsertHashTableEntry(&skmacLKey);
            *destination = *truncatedForSkmacL;
            delete truncatedForSkmacL;
            
            // Extract right part of MAC key
            std::string lengthForSkmacR = "08";
            std::string offsetForSkmacR = "08";
            std::string skmacKeyForR = "%skmac";
            std::string skmacRKey = "%skmac_r";
            
            std::string* skmacValueForR = GetOrInsertHashTableEntry(&skmacKeyForR);
            std::string tempSkmacValueForR = *skmacValueForR;
            
            std::string* truncatedForSkmacR = Clh_Truncate(new std::string(), this->data + 104, 105, &tempSkmacValueForR, &offsetForSkmacR, &lengthForSkmacR);
            destination = GetOrInsertHashTableEntry(&skmacRKey);
            *destination = *truncatedForSkmacR;
            delete truncatedForSkmacR;
            
            // MSE SET for digital signature
            std::string keyidKeyLookup = "%keyid";
            std::string algoidKeyLookup = "%algoid";
            
            std::string* algoidValue = GetOrInsertHashTableEntry(&algoidKeyLookup);
            std::string* keyidValue = GetOrInsertHashTableEntry(&keyidKeyLookup);
            
            std::string mseSetDSCmd = "002241b6068001" + *algoidValue + "8401" + *keyidValue;
            std::string mseSetDSResponse;
            CardLibBase::sendAPDU(this, &mseSetDSResponse, &mseSetDSCmd, 109);
            
            // Calculate hash of terminal data
            std::string terminalDataKeyForHash = "@terminal_data";
            std::string hashTerminalKey = "%sd";
            
            GetOrInsertHashTableEntry(&terminalDataKeyForHash);
            std::string* hashTerminalValue = Clh_SHA256(new std::string());
            
            destination = GetOrInsertHashTableEntry(&hashTerminalKey);
            *destination = *hashTerminalValue;
            delete hashTerminalValue;
            
            // Send PSO HASH command
            std::string hashTerminalKeyLookup = "%sd";
            std::string* hashTerminalValueForPso = GetOrInsertHashTableEntry(&hashTerminalKeyLookup);
            
            std::string psoHashCmd = "002a90a0229020" + *hashTerminalValueForPso;
            std::string psoHashResponse;
            CardLibBase::sendAPDU(this, &psoHashResponse, &psoHashCmd, 113);
            
            // Set header for PSO COMPUTE DIGITAL SIGNATURE
            std::string headerKey = "%header";
            destination = GetOrInsertHashTableEntry(&headerKey);
            *destination = "0c2a9e9a";
            
            // Prepare command header
            std::string headerKeyLookup = "%header";
            std::string chKey = "%ch";
            
            std::string* headerValue = GetOrInsertHashTableEntry(&headerKeyLookup);
            std::string commandHeader = *headerValue + "80000000";
            
            destination = GetOrInsertHashTableEntry(&chKey);
            *destination = commandHeader;
            
            // Add padding to signature data
            std::string padding = "01";
            std::string dataKey = "%data";
            
            std::string* dataTemplate = new std::string("8100");
            std::string* paddedData = Clh_AddPadding(new std::string(), this->data + 104, 118, &padding, dataTemplate);
            
            destination = GetOrInsertHashTableEntry(&dataKey);
            *destination = *paddedData;
            delete paddedData;
            delete dataTemplate;
            
            // Encrypt data for signature
            std::string encryptMode = "cbc";
            std::string skencKeyForEncrypt = "%skenc";
            std::string dataKeyLookup = "%data";
            std::string encdataKey = "%encdata";
            
            std::string* skencValueForEncrypt = GetOrInsertHashTableEntry(&skencKeyForEncrypt);
            std::string* dataValue = GetOrInsertHashTableEntry(&dataKeyLookup);
            
            std::string* encryptedDataValue = Clh_TripleDesEncrypt(new std::string(), this->data + 104, 119, dataValue, skencValueForEncrypt, &encryptMode);
            destination = GetOrInsertHashTableEntry(&encdataKey);
            *destination = *encryptedDataValue;
            delete encryptedDataValue;
            
            // Format encrypted data as TLV
            std::string icaoMode = "ICAO";
            std::string encdataKeyLookup = "%encdata";
            std::string edfb1Key = "%edfb_1";
            
            std::string* encdataValue = GetOrInsertHashTableEntry(&encdataKeyLookup);
            std::string* formattedEncData = new std::string("01" + *encdataValue);
            
            std::string* lenEncData = Clh_AddLen(new std::string(), formattedEncData, &icaoMode);
            std::string* tlvEncData = new std::string("87" + *lenEncData);
            
            destination = GetOrInsertHashTableEntry(&edfb1Key);
            *destination = *tlvEncData;
            delete tlvEncData;
            delete lenEncData;
            delete formattedEncData;
            
            // Increment SSC
            std::string hexBase = "h";
            std::string incValue = "01";
            std::string sscKeyForInc = "%ssc";
            std::string sscKeyForUpdate = "%ssc";
            
            std::string* sscValueForInc = GetOrInsertHashTableEntry(&sscKeyForInc);
            std::string* incrementedSsc = Clh_Add(new std::string(), this->data + 104, 121, sscValueForInc, &incValue, &hexBase);
            
            destination = GetOrInsertHashTableEntry(&sscKeyForUpdate);
            *destination = *incrementedSsc;
            delete incrementedSsc;
            
            // Add padding to TLV data
            std::string paddingForTlv = "01";
            std::string edfb1KeyLookup = "%edfb_1";
            std::string edfbKey = "%edfb";
            
            std::string* edfb1Value = GetOrInsertHashTableEntry(&edfb1KeyLookup);
            std::string tempEdfb1Value = *edfb1Value;
            
            std::string* paddedTlv = Clh_AddPadding(new std::string(), this->data + 104, 122, &paddingForTlv, &tempEdfb1Value);
            destination = GetOrInsertHashTableEntry(&edfbKey);
            *destination = *paddedTlv;
            delete paddedTlv;
            
            // Calculate MAC for command
            std::string modeForMac = "cbc";
            std::string skmacLKeyForMac = "%skmac_l";
            std::string edfbKeyLookup = "%edfb";
            std::string chKeyLookup = "%ch";
            std::string sscKeyForMac = "%ssc";
            std::string data1Key = "%data1";
            
            std::string* sscValueForMac = GetOrInsertHashTableEntry(&sscKeyForMac);
            std::string* chValueForMac = GetOrInsertHashTableEntry(&chKeyLookup);
            std::string* edfbValueForMac = GetOrInsertHashTableEntry(&edfbKeyLookup);
            
            std::string macInput = *sscValueForMac + *chValueForMac + *edfbValueForMac;
            
            std::string* skmacLValueForMac = GetOrInsertHashTableEntry(&skmacLKeyForMac);
            std::string* encryptedMacData = Clh_DesEncrypt(new std::string(), skmacLValueForMac, &modeForMac);
            
            destination = GetOrInsertHashTableEntry(&data1Key);
            *destination = *encryptedMacData;
            delete encryptedMacData;
            
            // Calculate offset for extract
            std::string decBase = "d";
            std::string data1KeyLookup = "%data1";
            std::string asc_1812A1C5C = "d";  // This may be a placeholder or constant
            
            GetOrInsertHashTableEntry(&data1KeyLookup);
            std::string* lenValue = Clh_GetLength(new std::string(), &decBase);
            
            destination = GetOrInsertHashTableEntry(&asc_1812A1C5C);
            *destination = *lenValue;
            delete lenValue;
            
            std::string offsetValue = "08";
            std::string offsetKey = "%offs";
            
            std::string* offsetResult = Clh_Sub(new std::string(), &offsetValue, &decBase);
            destination = GetOrInsertHashTableEntry(&offsetKey);
            *destination = *offsetResult;
            delete offsetResult;
            
            // Extract part of MAC data
            std::string lengthForExtract = "08";
            std::string offsetsKeyLookup = "%offs";
            std::string data1KeyForExtract = "%data1";
            std::string d1Key = "%d1";
            
            std::string* data1ValueForExtract = GetOrInsertHashTableEntry(&data1KeyForExtract);
            std::string tempData1ValueForExtract = *data1ValueForExtract;
            
            std::string* offsetsValueForExtract = GetOrInsertHashTableEntry(&offsetsKeyLookup);
            
            std::string* extractedD1 = Clh_Truncate(new std::string(), this->data + 104, 126, &tempData1ValueForExtract, offsetsValueForExtract, &lengthForExtract);
            destination = GetOrInsertHashTableEntry(&d1Key);
            *destination = *extractedD1;
            delete extractedD1;
            
            // Decrypt with right MAC key
            std::string modeForDecryptMac = "cbc";
            std::string skmacRKeyForDecrypt = "%skmac_r";
            std::string d1KeyLookup = "%d1";
            std::string d2Key = "%d2";
            
            std::string* skmacRValueForDecrypt = GetOrInsertHashTableEntry(&skmacRKeyForDecrypt);
            GetOrInsertHashTableEntry(&d1KeyLookup);
            
            std::string* decryptedD2 = Clh_DesDecrypt(new std::string(), skmacRValueForDecrypt, &modeForDecryptMac);
            destination = GetOrInsertHashTableEntry(&d2Key);
            *destination = *decryptedD2;
            delete decryptedD2;
            
            // Encrypt with left MAC key
            std::string modeForEncryptMac = "cbc";
            std::string skmacLKeyForEncrypt = "%skmac_l";
            std::string d2KeyLookup = "%d2";
            std::string mac1Key = "%mac1";
            
            std::string* skmacLValueForEncrypt = GetOrInsertHashTableEntry(&skmacLKeyForEncrypt);
            GetOrInsertHashTableEntry(&d2KeyLookup);
            
            std::string* encryptedMac1 = Clh_DesEncrypt(new std::string(), skmacLValueForEncrypt, &modeForEncryptMac);
            destination = GetOrInsertHashTableEntry(&mac1Key);
            *destination = *encryptedMac1;
            delete encryptedMac1;
            
            // Format MAC as TLV
            std::string mac1KeyLookup = "%mac1";
            std::string mac1KeyForTlv = "%mac1";
            
            std::string* mac1Value = GetOrInsertHashTableEntry(&mac1KeyLookup);
            std::string formattedMac = "8e08" + *mac1Value;
            
            destination = GetOrInsertHashTableEntry(&mac1KeyForTlv);
            *destination = formattedMac;
            
            // Combine TLV data and MAC
            std::string mac1KeyForCombine = "%mac1";
            std::string edfb1KeyForCombine = "%edfb_1";
            std::string totalKey = "%total";
            
            std::string* edfb1ValueForCombine = GetOrInsertHashTableEntry(&edfb1KeyForCombine);
            std::string* mac1ValueForCombine = GetOrInsertHashTableEntry(&mac1KeyForCombine);
            
            std::string combinedData = *edfb1ValueForCombine + *mac1ValueForCombine;
            destination = GetOrInsertHashTableEntry(&totalKey);
            *destination = combinedData;
            
            // Add length to total data
            std::string iso7816Mode = "ISO7816";
            std::string totalKeyLookup = "%total";
            std::string headerKeyForCommand = "%header";
            std::string signeddata1Key = "%signeddata1";
            
            std::string* totalValue = GetOrInsertHashTableEntry(&totalKeyLookup);
            std::string* totalWithLength = Clh_AddLen(new std::string(), totalValue, &iso7816Mode);
            
            std::string* headerValueForCommand = GetOrInsertHashTableEntry(&headerKeyForCommand);
            std::string command = *headerValueForCommand + *totalWithLength + "00";
            
            std::string* commandResult = CardLibBase::sendAPDU(this, new std::string(), &command, 133);
            destination = GetOrInsertHashTableEntry(&signeddata1Key);
            *destination = *commandResult;
            delete commandResult;
            delete totalWithLength;
            
            // Extract SW2 from response
            std::string lengthForSw2 = "01";
            std::string offsetForSw2 = "01";
            std::string lastResultKeyForSw = "%lastresult";
            std::string sw2Key = "%sw2";
            
            std::string* lastResultValueForSw = GetOrInsertHashTableEntry(&lastResultKeyForSw);
            std::string tempLastResultValueForSw = *lastResultValueForSw;
            
            std::string* extractedSw2 = Clh_Truncate(new std::string(), this->data + 104, 134, &tempLastResultValueForSw, &offsetForSw2, &lengthForSw2);
            destination = GetOrInsertHashTableEntry(&sw2Key);
            *destination = *extractedSw2;
            delete extractedSw2;
            
            // Get remaining signature data
            std::string sw2KeyLookup = "%sw2";
            std::string signeddata2Key = "%signeddata2";
            
            std::string* sw2Value = GetOrInsertHashTableEntry(&sw2KeyLookup);
            std::string getSignatureCmd = "00c00000" + *sw2Value;
            
            std::string* getSignatureResult = CardLibBase::sendAPDU(this, new std::string(), &getSignatureCmd, 135);
            destination = GetOrInsertHashTableEntry(&signeddata2Key);
            *destination = *getSignatureResult;
            delete getSignatureResult;
            
            // Combine signature data parts
            std::string signeddata2KeyLookup = "%signeddata2";
            std::string signeddata1KeyLookup = "%signeddata1";
            std::string signeddata3Key = "%signeddata3";
            
            std::string* signeddata1Value = GetOrInsertHashTableEntry(&signeddata1KeyLookup);
            std::string* signeddata2Value = GetOrInsertHashTableEntry(&signeddata2KeyLookup);
            
            std::string combinedSignature = *signeddata1Value + *signeddata2Value;
            destination = GetOrInsertHashTableEntry(&signeddata3Key);
            *destination = combinedSignature;
            
            // Extract tag from signature data
            std::string lengthForTag = "01";
            std::string offsetForTag = "01";
            std::string signeddata3KeyLookup = "%signeddata3";
            std::string tagKey = "%tag";
            
            std::string* signeddata3Value = GetOrInsertHashTableEntry(&signeddata3KeyLookup);
            std::string tempSigneddata3Value = *signeddata3Value;
            
            std::string* extractedTag = Clh_Truncate(new std::string(), this->data + 104, 138, &tempSigneddata3Value, &offsetForTag, &lengthForTag);
            destination = GetOrInsertHashTableEntry(&tagKey);
            *destination = *extractedTag;
            delete extractedTag;
            
            // Process based on tag type
            std::string tagKeyLookup = "%tag";
            std::string* tagValue = GetOrInsertHashTableEntry(&tagKeyLookup);
            
            if (*tagValue == "82") {
                // Process tag 82 (TLV with 2-byte length)
                std::string lengthForTagLen = "02";
                std::string offsetForTagLen = "02";
                std::string signeddata3KeyForLen = "%signeddata3";
                std::string lenKey = "%len";
                
                std::string* signeddata3ValueForLen = GetOrInsertHashTableEntry(&signeddata3KeyForLen);
                std::string tempSigneddata3ValueForLen = *signeddata3ValueForLen;
                
                std::string* extractedLen = Clh_Truncate(new std::string(), this->data + 104, 151, &tempSigneddata3ValueForLen, &offsetForTagLen, &lengthForTagLen);
                destination = GetOrInsertHashTableEntry(&lenKey);
                *destination = *extractedLen;
                delete extractedLen;
                
                // Convert hex length to decimal
                std::string lenKeyForHex = "%len";
                std::string lenKeyForDec = "%len";
                
                std::string* lenValueForHex = GetOrInsertHashTableEntry(&lenKeyForHex);
                std::string* convertedLen = Clh_Hex2Dec(new std::string(), this->data + 104, 152, lenValueForHex);
                
                destination = GetOrInsertHashTableEntry(&lenKeyForDec);
                *destination = *convertedLen;
                delete convertedLen;
                
                // Adjust length for extraction
                std::string oneValue = "01";
                std::string decBaseForLen = "d";
                std::string lenKeyForAdjust = "%len";
                std::string lenKeyForAdjusted = "%len";
                
                GetOrInsertHashTableEntry(&lenKeyForAdjust);
                std::string* adjustedLen = Clh_Sub(new std::string(), &oneValue, &decBaseForLen);
                
                destination = GetOrInsertHashTableEntry(&lenKeyForAdjusted);
                *destination = *adjustedLen;
                delete adjustedLen;
                
                // Extract encrypted data
                std::string offsetForEncrypted = "05";
                std::string lenKeyForExtract = "%len";
                std::string signeddata3KeyForEncrypted = "%signeddata3";
                std::string fKey = "%f";
                
                std::string* signeddata3ValueForEncrypted = GetOrInsertHashTableEntry(&signeddata3KeyForEncrypted);
                std::string tempSigneddata3ValueForEncrypted = *signeddata3ValueForEncrypted;
                
                std::string* lenValueForExtract = GetOrInsertHashTableEntry(&lenKeyForExtract);
                
                std::string* extractedEncrypted = Clh_Truncate(new std::string(), this->data + 104, 154, &tempSigneddata3ValueForEncrypted, &offsetForEncrypted, lenValueForExtract);
                destination = GetOrInsertHashTableEntry(&fKey);
                *destination = *extractedEncrypted;
                delete extractedEncrypted;
                
                // Decrypt data
                std::string modeForFinalDecrypt = "cbc";
                std::string skencKeyForFinalDecrypt = "%skenc";
                std::string fKeyLookup = "%f";
                std::string decKey = "%dec";
                
                std::string* skencValueForFinalDecrypt = GetOrInsertHashTableEntry(&skencKeyForFinalDecrypt);
                GetOrInsertHashTableEntry(&fKeyLookup);
                
                std::string* decryptedFinal = Clh_TripleDesDecrypt(new std::string(), skencValueForFinalDecrypt, &modeForFinalDecrypt);
                destination = GetOrInsertHashTableEntry(&decKey);
                *destination = *decryptedFinal;
                delete decryptedFinal;
                
                // Extract signed data
                std::string lengthForSigned = "0256";
                std::string offsetForSigned = "00";
                std::string decKeyLookup = "%dec";
                std::string signeddataKey = "%signeddata";
                
                std::string* decValueForSigned = GetOrInsertHashTableEntry(&decKeyLookup);
                std::string tempDecValueForSigned = *decValueForSigned;
                
                std::string* extractedSigned = Clh_Truncate(new std::string(), this->data + 104, 156, &tempDecValueForSigned, &offsetForSigned, &lengthForSigned);
                destination = GetOrInsertHashTableEntry(&signeddataKey);
                *destination = *extractedSigned;
                delete extractedSigned;
            } 
            else if (*tagValue == "01") {
                // Process tag 01 (possibly BER-TLV with 1-byte length)
                if (*tagValue == "01") {
                    // Extract length from signature data
                    std::string lengthForTagLen = "01";
                    std::string offsetForTagLen = "02";
                    std::string signeddata3KeyForLen = "%signeddata3";
                    std::string lenKey = "%len";
                    
                    std::string* signeddata3ValueForLen = GetOrInsertHashTableEntry(&signeddata3KeyForLen);
                    std::string tempSigneddata3ValueForLen = *signeddata3ValueForLen;
                    
                    std::string* extractedLen = Clh_Truncate(new std::string(), this->data + 104, 160, &tempSigneddata3ValueForLen, &offsetForTagLen, &lengthForTagLen);
                    destination = GetOrInsertHashTableEntry(&lenKey);
                    *destination = *extractedLen;
                    delete extractedLen;
                    
                    // Convert hex length to decimal
                    std::string lenKeyForHex = "%len";
                    std::string lenKeyForDec = "%len";
                    
                    std::string* lenValueForHex = GetOrInsertHashTableEntry(&lenKeyForHex);
                    std::string* convertedLen = Clh_Hex2Dec(new std::string(), this->data + 104, 161, lenValueForHex);
                    
                    destination = GetOrInsertHashTableEntry(&lenKeyForDec);
                    *destination = *convertedLen;
                    delete convertedLen;
                    
                    // Adjust length for extraction
                    std::string oneValue = "01";
                    std::string decBaseForLen = "d";
                    std::string lenKeyForAdjust = "%len";
                    std::string lenKeyForAdjusted = "%len";
                    
                    GetOrInsertHashTableEntry(&lenKeyForAdjust);
                    std::string* adjustedLen = Clh_Sub(new std::string(), &oneValue, &decBaseForLen);
                    
                    destination = GetOrInsertHashTableEntry(&lenKeyForAdjusted);
                    *destination = *adjustedLen;
                    delete adjustedLen;
                    
                    // Extract encrypted data
                    std::string offsetForEncrypted = "04";
                    std::string lenKeyForExtract = "%len";
                    std::string signeddata3KeyForEncrypted = "%signeddata3";
                    std::string fKey = "%f";
                    
                    std::string* signeddata3ValueForEncrypted = GetOrInsertHashTableEntry(&signeddata3KeyForEncrypted);
                    std::string tempSigneddata3ValueForEncrypted = *signeddata3ValueForEncrypted;
                    
                    std::string* lenValueForExtract = GetOrInsertHashTableEntry(&lenKeyForExtract);
                    
                    std::string* extractedEncrypted = Clh_Truncate(new std::string(), this->data + 104, 163, &tempSigneddata3ValueForEncrypted, &offsetForEncrypted, lenValueForExtract);
                    destination = GetOrInsertHashTableEntry(&fKey);
                    *destination = *extractedEncrypted;
                    delete extractedEncrypted;
                    
                    // Decrypt data
                    std::string modeForFinalDecrypt = "cbc";
                    std::string skencKeyForFinalDecrypt = "%skenc";
                    std::string fKeyLookup = "%f";
                    std::string decKey = "%dec";
                    
                    std::string* skencValueForFinalDecrypt = GetOrInsertHashTableEntry(&skencKeyForFinalDecrypt);
                    GetOrInsertHashTableEntry(&fKeyLookup);
                    
                    std::string* decryptedFinal = Clh_TripleDesDecrypt(new std::string(), skencValueForFinalDecrypt, &modeForFinalDecrypt);
                    destination = GetOrInsertHashTableEntry(&decKey);
                    *destination = *decryptedFinal;
                    delete decryptedFinal;
                    
                    // Extract signed data
                    std::string lengthForSigned = "0256";
                    std::string offsetForSigned = "00";
                    std::string decKeyLookup = "%dec";
                    std::string signeddataKey = "%signeddata";
                    
                    std::string* decValueForSigned = GetOrInsertHashTableEntry(&decKeyLookup);
                    std::string tempDecValueForSigned = *decValueForSigned;
                    
                    std::string* extractedSigned = Clh_Truncate(new std::string(), this->data + 104, 165, &tempDecValueForSigned, &offsetForSigned, &lengthForSigned);
                    destination = GetOrInsertHashTableEntry(&signeddataKey);
                    *destination = *extractedSigned;
                    delete extractedSigned;
                } else {
                    // Default processing for other tags
                    std::string lengthForTagLen = "01";
                    std::string offsetForTagLen = "01";
                    std::string signeddata3KeyForLen = "%signeddata3";
                    std::string lenKey = "%len";
                    
                    std::string* signeddata3ValueForLen = GetOrInsertHashTableEntry(&signeddata3KeyForLen);
                    std::string tempSigneddata3ValueForLen = *signeddata3ValueForLen;
                    
                    std::string* extractedLen = Clh_Truncate(new std::string(), this->data + 104, 141, &tempSigneddata3ValueForLen, &offsetForTagLen, &lengthForTagLen);
                    destination = GetOrInsertHashTableEntry(&lenKey);
                    *destination = *extractedLen;
                    delete extractedLen;
                    
                    // Convert hex length to decimal
                    std::string lenKeyForHex = "%len";
                    std::string lenKeyForDec = "%len";
                    
                    std::string* lenValueForHex = GetOrInsertHashTableEntry(&lenKeyForHex);
                    std::string* convertedLen = Clh_Hex2Dec(new std::string(), this->data + 104, 142, lenValueForHex);
                    
                    destination = GetOrInsertHashTableEntry(&lenKeyForDec);
                    *destination = *convertedLen;
                    delete convertedLen;
                    
                    // Adjust length for extraction
                    std::string oneValue = "01";
                    std::string decBaseForLen = "d";
                    std::string lenKeyForAdjust = "%len";
                    std::string lenKeyForAdjusted = "%len";
                    
                    GetOrInsertHashTableEntry(&lenKeyForAdjust);
                    std::string* adjustedLen = Clh_Sub(new std::string(), &oneValue, &decBaseForLen);
                    
                    destination = GetOrInsertHashTableEntry(&lenKeyForAdjusted);
                    *destination = *adjustedLen;
                    delete adjustedLen;
                    
                    // Extract encrypted data
                    std::string offsetForEncrypted = "03";
                    std::string lenKeyForExtract = "%len";
                    std::string signeddata3KeyForEncrypted = "%signeddata3";
                    std::string fKey = "%f";
                    
                    std::string* signeddata3ValueForEncrypted = GetOrInsertHashTableEntry(&signeddata3KeyForEncrypted);
                    std::string tempSigneddata3ValueForEncrypted = *signeddata3ValueForEncrypted;
                    
                    std::string* lenValueForExtract = GetOrInsertHashTableEntry(&lenKeyForExtract);
                    
                    std::string* extractedEncrypted = Clh_Truncate(new std::string(), this->data + 104, 144, &tempSigneddata3ValueForEncrypted, &offsetForEncrypted, lenValueForExtract);
                    destination = GetOrInsertHashTableEntry(&fKey);
                    *destination = *extractedEncrypted;
                    delete extractedEncrypted;
                    
                    // Decrypt data
                    std::string modeForFinalDecrypt = "cbc";
                    std::string skencKeyForFinalDecrypt = "%skenc";
                    std::string fKeyLookup = "%f";
                    std::string decKey = "%dec";
                    
                    std::string* skencValueForFinalDecrypt = GetOrInsertHashTableEntry(&skencKeyForFinalDecrypt);
                    GetOrInsertHashTableEntry(&fKeyLookup);
                    
                    std::string* decryptedFinal = Clh_TripleDesDecrypt(new std::string(), skencValueForFinalDecrypt, &modeForFinalDecrypt);
                    destination = GetOrInsertHashTableEntry(&decKey);
                    *destination = *decryptedFinal;
                    delete decryptedFinal;
                    
                    // Extract signed data
                    std::string lengthForSigned = "0256";
                    std::string offsetForSigned = "00";
                    std::string decKeyLookup = "%dec";
                    std::string signeddataKey = "%signeddata";
                    
                    std::string* decValueForSigned = GetOrInsertHashTableEntry(&decKeyLookup);
                    std::string tempDecValueForSigned = *decValueForSigned;
                    
                    std::string* extractedSigned = Clh_Truncate(new std::string(), this->data + 104, 146, &tempDecValueForSigned, &offsetForSigned, &lengthForSigned);
                    destination = GetOrInsertHashTableEntry(&signeddataKey);
                    *destination = *extractedSigned;
                    delete extractedSigned;
                }
            }
        } 
        else if (*swValue == "6983" || *swValue == "6984") {
            // PIN verification failed - blocked or invalid
            std::string* statusValue = GetOrInsertHashTableEntry(&statusKey);
            *statusValue = "f2";
        } 
        else {
            // Other PIN verification error
            std::string lengthForSw1 = "01";
            std::string offsetForSw1 = "00";
            std::string swKeyForParse = "%sw";
            std::string sw1Key = "%sw1";
            
            std::string* swValueForParse = GetOrInsertHashTableEntry(&swKeyForParse);
            std::string tempSwValueForParse = *swValueForParse;
            
            std::string* extractedSw1 = Clh_Truncate(new std::string(), this->data + 104, 45, &tempSwValueForParse, &offsetForSw1, &lengthForSw1);
            destination = GetOrInsertHashTableEntry(&sw1Key);
            *destination = *extractedSw1;
            delete extractedSw1;
            
            std::string lengthForSw2 = "01";
            std::string offsetForSw2 = "01";
            std::string swKeyForParse2 = "%sw";
            std::string sw2Key = "%sw2";
            
            std::string* swValueForParse2 = GetOrInsertHashTableEntry(&swKeyForParse2);
            std::string tempSwValueForParse2 = *swValueForParse2;
            
            std::string* extractedSw2 = Clh_Truncate(new std::string(), this->data + 104, 46, &tempSwValueForParse2, &offsetForSw2, &lengthForSw2);
            destination = GetOrInsertHashTableEntry(&sw2Key);
            *destination = *extractedSw2;
            delete extractedSw2;
            
            std::string sw1KeyLookup = "%sw1";
            std::string* sw1Value = GetOrInsertHashTableEntry(&sw1KeyLookup);
            
            if (*sw1Value == "63") {
                // PIN verification fail with tries remaining
                std::string* statusValue = GetOrInsertHashTableEntry(&statusKey);
                *statusValue = "f1";
            }
        }
        
        // Set successful return code
        std::string retcodeKeyForSuccess = "%returncode";
        destination = GetOrInsertHashTableEntry(&retcodeKeyForSuccess);
        *destination = "00";
        
        // Copy results to output parameters
        std::string signeddataKeyForOutput = "%signeddata";
        std::string* signeddataValue = GetOrInsertHashTableEntry(&signeddataKeyForOutput);
        **signeddata = *signeddataValue;
        
        std::string statusKeyForOutput = "%status";
        std::string* statusValue = GetOrInsertHashTableEntry(&statusKeyForOutput);
        **status = *statusValue;
        
        std::string retcodeKeyForOutput = "%returncode";
        std::string* retcodeValue = GetOrInsertHashTableEntry(&retcodeKeyForOutput);
        **returncode = *retcodeValue;
        
        // Clear function name
        lastCommand = "";
        
        return 0; // Success
    }
};

// Stubs for the utility functions (these would need actual implementations)
std::string* Clh_StringToLower(std::string* result, const std::string* input) {
    *result = *input;
    for (auto& c : *result) {
        c = std::tolower(c);
    }
    return result;
}

std::string* Clh_TripleDesEncrypt(std::string* result, void* context, int line, std::string* plaintext, std::string* key, std::string* mode) {
    // Placeholder for Triple DES encryption
    *result = "encrypted_" + *plaintext;
    return result;
}

std::string* Clh_TripleDesDecrypt(std::string* result, std::string* key, std::string* mode) {
    // Placeholder for Triple DES decryption
    *result = "decrypted_data";
    return result;
}

std::string* Clh_DesEncrypt(std::string* result, std::string* key, std::string* mode) {
    // Placeholder for DES encryption
    *result = "des_encrypted_data";
    return result;
}

std::string* Clh_DesDecrypt(std::string* result, std::string* context, std::string* mode) {
    // Placeholder for DES decryption
    *result = "des_decrypted_data";
    return result;
}

std::string* Clh_Truncate(std::string* result, void* context, int line, std::string* input, std::string* offset, std::string* length) {
    // Placeholder for string truncation function
    *result = input->substr(std::stoi(*offset, nullptr, 16), std::stoi(*length, nullptr, 16));
    return result;
}

std::string* Clh_Add(std::string* result, void* context, int64_t line, std::string* a, std::string* b, std::string* base) {
    // Placeholder for addition function
    *result = *a + *b; // This is simplified
    return result;
}

std::string* Clh_Sub(std::string* result, std::string* a, std::string* b) {
    // Placeholder for subtraction function
    *result = "subtracted_value";
    return result;
}

std::string* Clh_XOR(std::string* result, std::string* data) {
    // Placeholder for XOR function
    *result = "xored_data";
    return result;
}

std::string* Clh_SHA1(std::string* result) {
    // Placeholder for SHA1 hash function
    *result = "sha1_hash_result";
    return result;
}

std::string* Clh_SHA256(std::string* result) {
    // Placeholder for SHA256 hash function
    *result = "sha256_hash_result";
    return result;
}

std::string* Clh_GetLength(std::string* result, std::string* base) {
    // Placeholder for length calculation
    *result = "10"; // Default value
    return result;
}

std::string* Clh_AddPadding(std::string* result, void* context, int64_t line, std::string* padType, std::string* data) {
    // Placeholder for padding function
    *result = *data + "padded";
    return result;
}

std::string* Clh_AddLen(std::string* result, std::string* data, std::string* mode) {
    // Placeholder for length prefix function
    *result = "len_" + *data;
    return result;
}

std::string* Clh_Hex2Dec(std::string* result, void* context, int64_t line, std::string* hex) {
    // Placeholder for hex to decimal conversion
    *result = *hex; // This is simplified
    return result;
}

std::string* CardLibBase::sendAPDU(void* context, std::string* result, std::string* command, int line, StrObj** options) {
    // Placeholder for APDU command sending
    *result = "apdu_response_for_" + *command;
    return result;
}