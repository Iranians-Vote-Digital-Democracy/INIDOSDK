/*
 * Copyright (C) 2025 Iranians.vote
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program. If not, see <https://www.gnu.org/licenses/>.
 */

#include <cstdlib>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>
#include <winscard.h>

#pragma comment(lib, "winscard.lib")

// APDU commands from MDAS_AFIS_Check (using the working versions we tested)
static const BYTE SELECT_ISO7816_COMMAND[] = {0x00, 0xA4, 0x04, 0x00, 0x08,
                                              0xA0, 0x00, 0x00, 0x00, 0x18,
                                              0x30, 0x03, 0x01};

static const BYTE SELECT_MF_COMMAND[] = {0x00, 0xA4, 0x00, 0x00,
                                         0x02, 0x3F, 0x00};
static const BYTE SELECT_EF_DIR_COMMAND[] = {0x00, 0xA4, 0x01, 0x00,
                                             0x02, 0x03, 0x00};
static const BYTE SELECT_EF_CSN_COMMAND[] = {0x00, 0xA4, 0x02, 0x00,
                                             0x02, 0x03, 0x02};

// Status words
#define SW1_SUCCESS 0x90
#define SW2_SUCCESS 0x00
#define SW1_WRONG_LENGTH 0x6C
#define SW1_WRONG_PARAM 0x6B
#define SW1_FILE_NOT_FOUND 0x6A

// Helper function to print bytes in hex format
void printHexData(const char *label, const BYTE *data, size_t length) {
  std::cout << label << ": ";
  for (size_t i = 0; i < length; i++) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)data[i]
              << " ";
  }
  std::cout << std::dec << std::endl;
}

// Helper function to print vector in hex format
void printHexVector(const char *label, const std::vector<BYTE> &data) {
  std::cout << label << ": ";
  for (auto b : data) {
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
  }
  std::cout << std::dec << std::endl;
}

// Convert hex string to byte array
std::vector<BYTE> hexStringToBytes(const std::string &hexStr) {
  std::vector<BYTE> bytes;
  for (size_t i = 0; i < hexStr.length(); i += 2) {
    if (i + 1 < hexStr.length()) {
      std::string byteString = hexStr.substr(i, 2);
      BYTE byte = (BYTE)strtol(byteString.c_str(), nullptr, 16);
      bytes.push_back(byte);
    }
  }
  return bytes;
}

// Convert byte array to hex string
std::string bytesToHexString(const std::vector<BYTE> &data) {
  std::stringstream ss;
  for (auto b : data) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  }
  return ss.str();
}

/**
 * Transmits an APDU to the card and returns the data (excluding SW1/SW2).
 * Returns true if the transmission was successful.
 */
bool transmitAPDU(SCARDHANDLE cardHandle, const BYTE *apduCmd, size_t apduLen,
                  BYTE &sw1Out, BYTE &sw2Out, std::vector<BYTE> &response) {

  response.resize(256, 0);
  DWORD responseLen = static_cast<DWORD>(response.size());

  // Print the command being sent
  printHexData("Sending APDU", apduCmd, apduLen);

  LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, apduCmd, (DWORD)apduLen,
                              nullptr, response.data(), &responseLen);

  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Transmit failed. Error: 0x" << std::hex << status << std::dec
              << std::endl;
    return false;
  }

  // Check we have at least 2 bytes for SW1/SW2
  if (responseLen < 2) {
    std::cerr << "Invalid response length: " << responseLen << std::endl;
    return false;
  }

  // Extract the status bytes
  sw1Out = response[responseLen - 2];
  sw2Out = response[responseLen - 1];

  std::cout << "Response SW1:SW2 = " << std::hex << std::setw(2)
            << std::setfill('0') << (int)sw1Out << ":" << std::setw(2)
            << std::setfill('0') << (int)sw2Out << std::dec << std::endl;

  // Resize to remove SW1/SW2
  if (responseLen >= 2) {
    response.resize(responseLen - 2);
  } else {
    response.clear();
  }

  // Print the response
  printHexVector("Response data", response);

  return true;
}

// Helper class for string operations
class Clh {
public:
  static std::string Add(const std::string &data1, const std::string &data2,
                         const std::string &format) {
    if (format == "h") {
      // Hexadecimal addition
      unsigned int val1 = strtoul(data1.c_str(), nullptr, 16);
      unsigned int val2 = strtoul(data2.c_str(), nullptr, 16);
      char result[16];
      sprintf_s(result, sizeof(result), "%04x", val1 + val2);
      return std::string(result);
    } else {
      // Decimal addition
      unsigned int val1 = strtoul(data1.c_str(), nullptr, 10);
      unsigned int val2 = strtoul(data2.c_str(), nullptr, 10);
      return std::to_string(val1 + val2);
    }
  }

  static std::string Truncate(const std::string &input,
                              const std::string &posStr,
                              const std::string &lenStr) {
    int pos = strtoul(posStr.c_str(), nullptr, 16) *
              2; // Position in hex string (2 chars per byte)
    int len = strtoul(lenStr.c_str(), nullptr, 16) * 2; // Length in hex string

    std::cout << "Truncate: input=" << input << ", pos=" << pos
              << ", len=" << len << std::endl;

    if (pos >= input.length())
      return "";

    if (pos + len > input.length())
      len = input.length() - pos;

    return input.substr(pos, len);
  }
};

int GetCardHandle(SCARDHANDLE &cardHandle, SCARDCONTEXT &context) {
  memset(&context, 0, sizeof(context));
  LONG status =
      SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Failed to establish context. Error: 0x" << std::hex << status
              << std::dec << std::endl;
    return EXIT_FAILURE;
  }

  // List readers
  LPSTR readersStr = nullptr;
  DWORD readersLen = SCARD_AUTOALLOCATE;
  status = SCardListReadersA(context, nullptr, (LPSTR)&readersStr, &readersLen);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Failed to list readers. Error: 0x" << std::hex << status
              << std::dec << std::endl;
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  // Convert multi-string to vector
  std::vector<std::string> readers;
  {
    LPSTR current = readersStr;
    while (current && *current) {
      readers.push_back(current);
      current += strlen(current) + 1;
    }
  }
  SCardFreeMemory(context, readersStr);

  if (readers.empty()) {
    std::cerr << "No readers found." << std::endl;
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  // Print available readers
  std::cout << "Available readers:" << std::endl;
  for (size_t i = 0; i < readers.size(); i++) {
    std::cout << i << ": " << readers[i] << std::endl;
  }

  // Connect to the first reader
  DWORD activeProtocol;
  status = SCardConnectA(context, readers[0].c_str(), SCARD_SHARE_SHARED,
                         SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &cardHandle,
                         &activeProtocol);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Failed to connect to " << readers[0] << ". Error: 0x"
              << std::hex << status << std::dec << std::endl;
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  std::cout << "Successfully connected to reader: " << readers[0] << std::endl;

  // Get ATR (Answer To Reset) to identify the card
  BYTE atrBuffer[36];
  DWORD atrLength = sizeof(atrBuffer);
  DWORD dwState;
  LPSTR readerName = NULL;
  DWORD readerLen = SCARD_AUTOALLOCATE;

  status = SCardStatusA(cardHandle, (LPSTR)&readerName, &readerLen, &dwState,
                        &activeProtocol, atrBuffer, &atrLength);
  if (status == SCARD_S_SUCCESS && atrLength > 0) {
    std::cout << "Card ATR: ";
    for (DWORD i = 0; i < atrLength; i++) {
      std::cout << std::hex << std::setw(2) << std::setfill('0')
                << (int)atrBuffer[i] << " ";
    }
    std::cout << std::dec << std::endl;
  }
  SCardFreeMemory(context, readerName);

  return 0;
}

bool performAFISCheck(SCARDHANDLE cardHandle, std::string &afisCheckResult) {
  std::unordered_map<std::string, std::string> variables;

  // Initialize variables as in the MDAS_AFIS_Check function
  variables["%returncode"] = "ff";
  variables["%afischeck"] = "";
  variables["%p1p2"] = "0000";
  variables["%d"] = "00";
  variables["%temp"] = "";

  std::cout << "\n==== Starting AFIS Check ====\n" << std::endl;

  try {
    // 1. Select ISO7816 application
    std::cout << "\n-- Selecting ISO7816 application --" << std::endl;
    BYTE sw1, sw2;
    std::vector<BYTE> response;

    if (!transmitAPDU(cardHandle, SELECT_ISO7816_COMMAND,
                      sizeof(SELECT_ISO7816_COMMAND), sw1, sw2, response)) {
      std::cerr << "Failed to select ISO7816 application" << std::endl;
      variables["%returncode"] = "ff";
      return false;
    }

    // Record the result status
    char statusStr[5];
    sprintf_s(statusStr, sizeof(statusStr), "%02x%02x", sw1, sw2);
    variables["%res"] = statusStr;
    variables["%lastresult"] = statusStr;

    // 2. Select MF
    std::cout << "\n-- Selecting MF --" << std::endl;
    if (!transmitAPDU(cardHandle, SELECT_MF_COMMAND, sizeof(SELECT_MF_COMMAND),
                      sw1, sw2, response)) {
      std::cerr << "Failed to select MF" << std::endl;
      variables["%returncode"] = "ff";
      return false;
    }

    // Record the result status
    sprintf_s(statusStr, sizeof(statusStr), "%02x%02x", sw1, sw2);
    variables["%res"] = statusStr;
    variables["%lastresult"] = statusStr;

    // 3. Select EF_DIR
    std::cout << "\n-- Selecting EF_DIR --" << std::endl;
    if (!transmitAPDU(cardHandle, SELECT_EF_DIR_COMMAND,
                      sizeof(SELECT_EF_DIR_COMMAND), sw1, sw2, response)) {
      std::cerr << "Failed to select EF_DIR" << std::endl;
      variables["%returncode"] = "ff";
      return false;
    }

    // Record the result status
    sprintf_s(statusStr, sizeof(statusStr), "%02x%02x", sw1, sw2);
    variables["%res"] = statusStr;
    variables["%lastresult"] = statusStr;

    // 4. Select EF_CSN
    std::cout << "\n-- Selecting EF_CSN --" << std::endl;
    if (!transmitAPDU(cardHandle, SELECT_EF_CSN_COMMAND,
                      sizeof(SELECT_EF_CSN_COMMAND), sw1, sw2, response)) {
      std::cerr << "Failed to select EF_CSN" << std::endl;
      variables["%returncode"] = "ff";
      return false;
    }

    // Record the result status
    sprintf_s(statusStr, sizeof(statusStr), "%02x%02x", sw1, sw2);
    variables["%res"] = statusStr;
    variables["%lastresult"] = statusStr;

    // 5. Start READ BINARY loop with dynamic P1P2 update
    std::cout << "\n-- Reading binary data --" << std::endl;
    bool continueReading = true;
    int readCount = 0;

    while (continueReading &&
           readCount < 10) { // Limit to 10 reads to prevent infinite loops
      readCount++;

      // Prepare READ BINARY command with current P1P2
      std::string p1p2 = variables["%p1p2"];
      std::cout << "Current P1P2: " << p1p2 << std::endl;

      BYTE readBinaryCmd[] = {0x00, 0xB0, 0x00, 0x00, 0xF8};
      readBinaryCmd[2] =
          (BYTE)strtoul(p1p2.substr(0, 2).c_str(), nullptr, 16); // P1
      readBinaryCmd[3] =
          (BYTE)strtoul(p1p2.substr(2, 2).c_str(), nullptr, 16); // P2

      // Send READ BINARY command
      if (!transmitAPDU(cardHandle, readBinaryCmd, sizeof(readBinaryCmd), sw1,
                        sw2, response)) {
        std::cerr << "Failed to read binary data" << std::endl;
        // Note the failure but continue with any data we might have
        continueReading = false;
      } else {
        // Record the status
        sprintf_s(statusStr, sizeof(statusStr), "%02x%02x", sw1, sw2);
        variables["%res"] = statusStr;
        variables["%lastresult"] = statusStr;

        // Check status words for special handling
        if (sw1 == SW1_SUCCESS && sw2 == SW2_SUCCESS) {
          // Success - store data and prepare for next read
          variables["%outi"] = bytesToHexString(response);
          variables["%temp"] += variables["%outi"];

          std::cout << "Read successful, data length: " << response.size()
                    << std::endl;

          // Update P1P2 for next read (increment by 3E (62) bytes)
          variables["%p1p2"] = Clh::Add(p1p2, "003e", "h");

          // If we received less than the maximum, we're done
          if (response.size() < 0xF8) {
            std::cout << "Received less than maximum data, stopping read loop"
                      << std::endl;
            continueReading = false;
          }
        } else if (sw1 == SW1_WRONG_LENGTH) { // 6C xx
          variables["%tres1"] = "6c";
          variables["%tres2"] = std::string(1, (char)sw2);

          std::cout << "Wrong length indicated by card, should use: "
                    << (int)sw2 << std::endl;

          // Create a new command with correct length
          readBinaryCmd[4] = sw2;

          // Retry with correct length
          if (!transmitAPDU(cardHandle, readBinaryCmd, sizeof(readBinaryCmd),
                            sw1, sw2, response)) {
            std::cerr << "Failed to read binary data with corrected length"
                      << std::endl;
            continueReading = false;
          } else {
            // Record the result
            sprintf_s(statusStr, sizeof(statusStr), "%02x%02x", sw1, sw2);
            variables["%res"] = statusStr;
            variables["%lastresult"] = statusStr;

            if (sw1 == SW1_SUCCESS && sw2 == SW2_SUCCESS) {
              variables["%outi"] = bytesToHexString(response);
              continueReading = false; // Stop after getting corrected data
            } else {
              continueReading = false; // Error, stop reading
            }
          }
        } else if (sw1 == SW1_WRONG_PARAM && sw2 == 0x00) { // 6B 00
          // Read beyond end of file
          std::cout << "Read beyond end of file (6B00)" << std::endl;
          variables["%res"] = "6b00";
          continueReading = false;
        } else {
          // Other error
          std::cerr << "Error in READ BINARY: " << std::hex << (int)sw1 << " "
                    << (int)sw2 << std::dec << std::endl;
          continueReading = false;
        }
      }
    }

    std::cout << "\n-- Processing metadata --" << std::endl;

    // Process metadata if we have any in temp buffer
    if (!variables["%temp"].empty() || !variables["%outi"].empty()) {
      std::cout << "Creating meta_info from collected data" << std::endl;

      // Create meta_info from temp + outi
      variables["%meta_info"] = variables["%temp"] + variables["%outi"];

      // Manual search for tag "ad" in the hex string
      std::cout << "Searching for tag 'ad' in metadata" << std::endl;
      std::string metadata = variables["%meta_info"];
      size_t pos = 0;
      bool tagFound = false;

      while (pos < metadata.length() -
                       4) { // Need at least 4 more chars for tag + length
        // Check for tag "ad"
        if (metadata.substr(pos, 2) == "ad") {
          std::cout << "Found 'ad' tag at position " << pos << std::endl;

          // Get length (next byte)
          if (pos + 2 < metadata.length()) {
            std::string lenHex = metadata.substr(pos + 2, 2);
            int lenValue = strtoul(lenHex.c_str(), nullptr, 16);
            std::cout << "Length of 'ad' data: " << lenValue
                      << " bytes (hex: " << lenHex << ")" << std::endl;

            // Make sure we have enough data
            if (pos + 4 + (lenValue * 2) <= metadata.length()) {
              // Extract the data (starts after tag + length)
              variables["%afischeck"] = metadata.substr(pos + 4, lenValue * 2);
              std::cout << "AFIS check data: " << variables["%afischeck"]
                        << std::endl;
              tagFound = true;
              break;
            } else {
              std::cerr << "Not enough data for AFIS value" << std::endl;
            }
          }
        }
        pos += 2; // Move to next byte position
      }

      if (!tagFound) {
        std::cout << "AFIS tag 'ad' not found in metadata" << std::endl;
        // Provide as much metadata as possible for debugging
        variables["%afischeck"] = "TAG_NOT_FOUND";
      }
    } else {
      std::cout << "No data collected, cannot process metadata" << std::endl;
      variables["%afischeck"] = "NO_DATA_COLLECTED";
    }

    // Set return code to success if we've made it this far
    variables["%returncode"] = "00";

    // Return results
    afisCheckResult = variables["%afischeck"];
    return variables["%returncode"] == "00";
  } catch (const std::exception &e) {
    std::cerr << "Exception in performAFISCheck: " << e.what() << std::endl;
    variables["%returncode"] = "ff";
    afisCheckResult = "EXCEPTION";
    return false;
  }
}

int main() {
  SCARDHANDLE cardHandle;
  SCARDCONTEXT context;

  std::cout << "Connecting to card reader..." << std::endl;

  if (GetCardHandle(cardHandle, context) != 0) {
    printf("Attempting to connect again in 1 second\n");
    Sleep(1000);
    if (GetCardHandle(cardHandle, context) != 0)
      return 1;
  }

  // Perform AFIS check
  std::string afisCheckResult;
  bool success = false;

  try {
    success = performAFISCheck(cardHandle, afisCheckResult);
  } catch (const std::exception &e) {
    std::cerr << "Exception while performing AFIS check: " << e.what()
              << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  // Print results
  std::cout << "\n==== AFIS Check Results ====\n" << std::endl;
  std::cout << "AFIS Check Result: " << afisCheckResult << std::endl;
  std::cout << "Status: " << (success ? "Success" : "Failed") << std::endl;

  // Cleanup
  std::cout << "\nDisconnecting from card..." << std::endl;
  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}

/*

Understanding AFIS Check in Smart Card Applications
Based on your code and output, the AFIS (Automated Fingerprint Identification
System) check is a specific operation that retrieves biometric verification data
from a smart card. Here's a detailed explanation: What is AFIS Check? AFIS check
is a process that reads specific data from a smart card that relates to
fingerprint verification. It checks whether the card contains valid fingerprint
templates or verification status data that can be used for identity validation.
What It's Looking For
The code follows a sequence of operations to:

Select specific applications and files on the card (ISO7816 application, Master
File, Directory File, and Card Serial Number File) Read binary data from the
card's memory Search for a specific tag - in this case, the tag "ad" within the
retrieved data Extract the value associated with this tag (which was "00" in
your output)

Significance of the Result
The value "00" found under the "ad" tag generally indicates the fingerprint
verification status:

00 typically means "AFIS data not enrolled" or "fingerprint verification not
required" Other values might indicate various states like "verified," "failed
verification," or "verification required"

This information is critical for systems that use smart cards for identity
verification with biometric components. The check helps determine:

Whether the card requires fingerprint verification
The current status of that verification
Whether the card has been properly enrolled in an AFIS system

Why This Check Is Important
This check would be important in contexts like:

Government ID systems (national ID cards, driver's licenses)
Access control systems that require both card and biometric verification
Border control or high-security facilities
Financial transaction authorization with biometric verification

The "00" result suggests that this particular card either:

Doesn't have fingerprint verification enabled
Hasn't been enrolled with fingerprint data
Is configured not to require biometric verification

The check gives systems information about how to handle the card in subsequent
operations - whether to request a fingerprint scan, grant access based on card
data alone, or take other actions based on security policies.
*/