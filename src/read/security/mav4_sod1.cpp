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

// APDU commands from MAV4_General_1::Read_SOD1
static const BYTE SELECT_APPLET[] = {0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00,
                                     0x00, 0x00, 0x18, 0x30, 0x03, 0x01, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const BYTE SELECT_MF[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
static const BYTE SELECT_DF[] = {0x00, 0xA4, 0x01, 0x00, 0x02, 0x02, 0x00};
static const BYTE SELECT_EF[] = {0x00, 0xA4, 0x02, 0x00, 0x02, 0x02, 0x05};
static const BYTE READ_BINARY[] = {0x00, 0xB0, 0x00, 0x00,
                                   0xEC}; // We'll update P1P2 based on response

// Alternative APDU commands to try
static const BYTE SELECT_CARD_MANAGER[] = {0x00, 0xA4, 0x04, 0x00, 0x08,
                                           0xA0, 0x00, 0x00, 0x00, 0x18,
                                           0x43, 0x4D, 0x00};
static const BYTE GET_CPLC_COMMAND[] = {0x80, 0xCA, 0x9F, 0x7F, 0x2D};
static const BYTE GET_TAG0101_COMMAND[] = {0x80, 0xCA, 0x01, 0x01, 0x15};

#define SW1_SUCCESS 0x90
#define SW2_SUCCESS 0x00

// Special status words that need handling
#define SW1_WRONG_LENGTH 0x6C
#define SW1_WRONG_PARAMS 0x6B
#define SW2_WRONG_PARAMS 0x00
#define SW1_SECURITY_NOT_SATISFIED 0x69
#define SW2_SECURITY_NOT_SATISFIED 0x82

/**
 * Transmits an APDU to the card and returns the data and SW1/SW2.
 * Unlike the original code, we need SW1/SW2 for special handling.
 */
std::pair<std::vector<BYTE>, std::pair<BYTE, BYTE>>
transmitAPDUWithSW(SCARDHANDLE cardHandle, const BYTE *apduCmd, size_t apduLen,
                   bool ignoreErrors = false) {
  std::vector<BYTE> response(256, 0);
  DWORD responseLen = static_cast<DWORD>(response.size());

  LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, apduCmd, (DWORD)apduLen,
                              nullptr, response.data(), &responseLen);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Transmit failed. Error: " << std::hex << status << std::endl;
    exit(EXIT_FAILURE);
  }

  // Check we have at least 2 bytes for SW1/SW2
  if (responseLen < 2) {
    std::cerr << "Invalid response length: " << responseLen << std::endl;
    exit(EXIT_FAILURE);
  }

  // Get the status bytes
  BYTE sw1 = response[responseLen - 2];
  BYTE sw2 = response[responseLen - 1];

  // Print status words for debugging
  std::cout << "SW1: " << std::hex << (int)sw1 << ", SW2: " << (int)sw2
            << std::dec << std::endl;

  // Resize to remove SW1/SW2
  response.resize(responseLen - 2);

  return {response, {sw1, sw2}};
}

/**
 * Extracts `length` bytes starting at `startOffset` from `input`.
 * If out of range, returns an empty vector.
 */
std::vector<BYTE> truncateData(const std::vector<BYTE> &input,
                               size_t startOffset, size_t length) {
  if (startOffset >= input.size())
    return {};

  size_t endOffset = startOffset + length;
  if (endOffset > input.size())
    endOffset = input.size();

  return std::vector<BYTE>(input.begin() + startOffset,
                           input.begin() + endOffset);
}

/**
 * Hex to decimal conversion (similar to Clh::Hex2Dec)
 */
std::string hexToDecString(const std::string &hexStr) {
  unsigned long long value = strtoull(hexStr.c_str(), nullptr, 16);
  return std::to_string(value);
}

/**
 * Convert bytes to hex string
 */
std::string bytesToHexString(const std::vector<BYTE> &data) {
  std::stringstream ss;
  for (auto b : data) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)b;
  }
  return ss.str();
}

/**
 * Print bytes in hex format
 */
void printHex(const std::vector<BYTE> &data, const char *label) {
  std::cout << label << ": ";
  for (auto b : data)
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
  std::cout << std::dec << std::endl;
}

/**
 * Try various SELECT commands to find one that works
 */
bool trySelectCommands(SCARDHANDLE cardHandle) {
  std::cout << "Trying SELECT Card Manager..." << std::endl;
  auto [resp1, sw1] = transmitAPDUWithSW(cardHandle, SELECT_CARD_MANAGER,
                                         sizeof(SELECT_CARD_MANAGER), true);
  if (sw1.first == SW1_SUCCESS && sw1.second == SW2_SUCCESS) {
    std::cout << "SELECT Card Manager succeeded" << std::endl;
    return true;
  }

  std::cout << "Trying SELECT Applet..." << std::endl;
  auto [resp2, sw2] = transmitAPDUWithSW(cardHandle, SELECT_APPLET,
                                         sizeof(SELECT_APPLET), true);
  if (sw2.first == SW1_SUCCESS && sw2.second == SW2_SUCCESS) {
    std::cout << "SELECT Applet succeeded" << std::endl;
    return true;
  }

  std::cout << "Trying alternative protocol sequences..." << std::endl;

  // Try SELECT MF first
  auto [resp3, sw3] =
      transmitAPDUWithSW(cardHandle, SELECT_MF, sizeof(SELECT_MF), true);
  if (sw3.first == SW1_SUCCESS && sw3.second == SW2_SUCCESS) {
    std::cout << "SELECT MF succeeded" << std::endl;

    // Then try SELECT DF
    auto [resp4, sw4] =
        transmitAPDUWithSW(cardHandle, SELECT_DF, sizeof(SELECT_DF), true);
    if (sw4.first == SW1_SUCCESS && sw4.second == SW2_SUCCESS) {
      std::cout << "SELECT DF succeeded" << std::endl;
      return true;
    }
  }

  return false;
}

/**
 * Implementation of Read_SOD1 function with alternative approach for security
 * issues
 */
std::string ReadSOD1(SCARDHANDLE cardHandle) {
  std::unordered_map<std::string, std::string> hashTable;
  std::string tempData = "";
  std::vector<BYTE> responseData;
  std::string sod1 = "";

  std::cout << "Starting READ_SOD1 sequence..." << std::endl;

  // First, try to select the applet
  try {
    auto [resp1, sw1] =
        transmitAPDUWithSW(cardHandle, SELECT_APPLET, sizeof(SELECT_APPLET));

    // If security error, try alternative selection methods
    if (sw1.first == SW1_SECURITY_NOT_SATISFIED &&
        sw1.second == SW2_SECURITY_NOT_SATISFIED) {
      std::cout
          << "Security status not satisfied. Trying alternative approaches..."
          << std::endl;
      if (!trySelectCommands(cardHandle)) {
        std::cout << "Unable to select an applet or file on the card."
                  << std::endl;
        return "ERROR_SECURITY_NOT_SATISFIED";
      }
    }

    // Continue with standard sequence
    auto [resp2, sw2] =
        transmitAPDUWithSW(cardHandle, SELECT_MF, sizeof(SELECT_MF));
    auto [resp3, sw3] =
        transmitAPDUWithSW(cardHandle, SELECT_DF, sizeof(SELECT_DF));
    auto [resp4, sw4] =
        transmitAPDUWithSW(cardHandle, SELECT_EF, sizeof(SELECT_EF));

  } catch (...) {
    std::cout << "Error during file selection. Trying alternative approach..."
              << std::endl;

    // Try the original CSN/CRN approach
    try {
      // (1) SELECT Card Manager
      auto [respCM, swCM] = transmitAPDUWithSW(cardHandle, SELECT_CARD_MANAGER,
                                               sizeof(SELECT_CARD_MANAGER));

      // (2) Read CPLC data
      auto [cplcData, swCPLC] = transmitAPDUWithSW(cardHandle, GET_CPLC_COMMAND,
                                                   sizeof(GET_CPLC_COMMAND));
      if (swCPLC.first == SW1_SUCCESS && swCPLC.second == SW2_SUCCESS) {
        std::vector<BYTE> csn = truncateData(cplcData, 0x13, 0x08);
        printHex(csn, "CSN");
        return bytesToHexString(csn);
      }

      // (3) Read Tag 0101
      auto [tagData, swTag] = transmitAPDUWithSW(
          cardHandle, GET_TAG0101_COMMAND, sizeof(GET_TAG0101_COMMAND));
      if (swTag.first == SW1_SUCCESS && swTag.second == SW2_SUCCESS) {
        std::vector<BYTE> crn = truncateData(tagData, 0x03, 0x10);
        printHex(crn, "CRN");
        return bytesToHexString(crn);
      }

    } catch (...) {
      std::cout << "Alternative approach also failed." << std::endl;
      return "ERROR_ALTERNATIVE_APPROACH_FAILED";
    }
  }

  // Set initial P1P2 to 0000
  std::string p1p2 = "0000";

  // Main loop - keeps reading until successful
  bool success = false;
  int attemptCount = 0;

  while (!success && attemptCount < 5) {
    attemptCount++;
    std::cout << "Attempt " << attemptCount << " with P1P2: " << p1p2
              << std::endl;

    try {
      // Create READ BINARY command with current P1P2
      std::vector<BYTE> readBinaryCmd = {0x00, 0xB0};

      // Convert p1p2 from hex string to bytes and add to command
      BYTE p1 = (BYTE)strtoul(p1p2.substr(0, 2).c_str(), nullptr, 16);
      BYTE p2 = (BYTE)strtoul(p1p2.substr(2, 2).c_str(), nullptr, 16);
      readBinaryCmd.push_back(p1);
      readBinaryCmd.push_back(p2);
      readBinaryCmd.push_back(0xEC); // Le (expected length)

      // Send READ BINARY command
      auto [respData, swCodes] = transmitAPDUWithSW(
          cardHandle, readBinaryCmd.data(), readBinaryCmd.size());

      // Print response for debugging
      printHex(respData, "Response Data");

      // Store the response data
      std::string respHex = bytesToHexString(respData);

      // Check status words and update P1P2 if needed
      if (swCodes.first == SW1_SUCCESS && swCodes.second == SW2_SUCCESS) {
        // Success - add data to SOD1
        tempData += respHex;
        success = true;
        std::cout << "Successfully read data" << std::endl;
      } else if (swCodes.first == SW1_WRONG_LENGTH) {
        // Wrong length - need to adjust Le
        tempData += respHex;

        // Update P1P2 for next read - we add 0x3B to P1P2 (as in Clh::Add from
        // the code)
        unsigned int p1p2Value = strtoul(p1p2.c_str(), nullptr, 16);
        p1p2Value += 0x3B;

        // Convert back to hex string
        std::stringstream ss;
        ss << std::hex << std::setw(4) << std::setfill('0') << p1p2Value;
        p1p2 = ss.str();
        std::cout << "Updated P1P2 to: " << p1p2 << std::endl;
      } else if (swCodes.first == SW1_WRONG_PARAMS &&
                 swCodes.second == SW2_WRONG_PARAMS) {
        // Wrong parameters - add data and finish
        tempData += respHex;
        success = true;
        std::cout << "Received 6B00, finished reading" << std::endl;
      } else if (swCodes.first == SW1_SECURITY_NOT_SATISFIED &&
                 swCodes.second == SW2_SECURITY_NOT_SATISFIED) {
        std::cout << "Security condition not satisfied for READ BINARY"
                  << std::endl;

        // Try alternative commands
        auto [cplcData, swCPLC] = transmitAPDUWithSW(
            cardHandle, GET_CPLC_COMMAND, sizeof(GET_CPLC_COMMAND));
        if (swCPLC.first == SW1_SUCCESS && swCPLC.second == SW2_SUCCESS) {
          std::vector<BYTE> csn = truncateData(cplcData, 0x13, 0x08);
          printHex(csn, "CSN (alternative)");
          return bytesToHexString(csn);
        }
        break;
      } else {
        // Other error - try different P1P2 values
        p1p2 = "0100"; // Try a different offset
        std::cout << "Trying different P1P2: " << p1p2 << std::endl;
      }

    } catch (...) {
      std::cout << "Exception during read attempt " << attemptCount
                << std::endl;
      p1p2 = "0100"; // Try a different offset
    }
  }

  if (!success && tempData.empty()) {
    return "ERROR_READING_CARD";
  }

  // If we have data but couldn't complete the read, return what we have
  if (!tempData.empty()) {
    std::cout << "Returning partial data: " << tempData << std::endl;
    return tempData;
  }

  // Extract tag and length from SOD1 (similar to the truncate operations in the
  // code)
  if (tempData.length() < 6) {
    return tempData; // Not enough data to extract tag/length
  }

  std::string tag = tempData.substr(2, 2);
  std::cout << "Tag: " << tag << std::endl;

  size_t dataOffset, lengthBytes;
  std::string lengthHex;

  if (tag.empty() || tag == "82") {
    // Get length from position 4-6 (2 bytes)
    if (tempData.length() >= 8) {
      lengthHex = tempData.substr(4, 4);
      std::string lengthDec = hexToDecString(lengthHex);
      std::cout << "Length (decimal): " << lengthDec << std::endl;
      dataOffset = 8; // After tag and length

      // Extract the actual SOD1 data
      if (tempData.length() > dataOffset) {
        sod1 = tempData.substr(dataOffset);
      } else {
        sod1 = tempData;
      }
    } else {
      sod1 = tempData;
    }
  } else {
    // Get length from position 6-8 (2 bytes)
    if (tempData.length() >= 10) {
      lengthHex = tempData.substr(6, 4);
      std::string lengthDec = hexToDecString(lengthHex);
      std::cout << "Length (decimal): " << lengthDec << std::endl;
      dataOffset = 10; // Alternative offset

      // Extract the actual SOD1 data
      if (tempData.length() > dataOffset) {
        sod1 = tempData.substr(dataOffset);
      } else {
        sod1 = tempData;
      }
    } else {
      sod1 = tempData;
    }
  }

  return sod1;
}

int GetCardHandle(SCARDHANDLE &cardHandle, SCARDCONTEXT &context) {
  memset(&context, 0, sizeof(context));
  LONG status =
      SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Failed to establish context. Error: 0x" << std::hex << status
              << std::endl;
    return EXIT_FAILURE;
  }

  // (2) List readers
  LPSTR readersStr = nullptr;
  DWORD readersLen = SCARD_AUTOALLOCATE;
  status = SCardListReadersA(context, nullptr, (LPSTR)&readersStr, &readersLen);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Failed to list readers. Error: 0x" << std::hex << status
              << std::endl;
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

  std::cout << "Available readers:" << std::endl;
  for (size_t i = 0; i < readers.size(); i++) {
    std::cout << i << ": " << readers[i] << std::endl;
  }

  // (3) Connect to the first reader
  DWORD activeProtocol;
  status = SCardConnectA(context, readers[0].c_str(), SCARD_SHARE_SHARED,
                         SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &cardHandle,
                         &activeProtocol);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Failed to connect to " << readers[0] << ". Error: 0x"
              << std::hex << status << std::endl;
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  std::cout << "Connected to reader: " << readers[0] << std::endl;
  std::cout << "Protocol: "
            << (activeProtocol == SCARD_PROTOCOL_T0   ? "T=0"
                : activeProtocol == SCARD_PROTOCOL_T1 ? "T=1"
                                                      : "Unknown")
            << std::endl;

  return 0;
}

int main() {
  SCARDHANDLE cardHandle;
  SCARDCONTEXT context;
  if (GetCardHandle(cardHandle, context) != 0) {
    printf("Attempting to connect again in 1 second\n");
    Sleep(1000);
    if (GetCardHandle(cardHandle, context) != 0)
      return 1;
  }

  // Read SOD1 data from the card
  std::string sod1;
  try {
    sod1 = ReadSOD1(cardHandle);
  } catch (const std::exception &e) {
    std::cerr << "Exception while reading SOD1: " << e.what() << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  } catch (...) {
    std::cerr << "Unknown exception while reading SOD1." << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  // Print results
  std::cout << "SOD1: " << sod1 << std::endl;

  // Cleanup
  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}