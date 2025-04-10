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
#include <vector>
#include <windows.h>
#include <winscard.h>

#pragma comment(lib, "winscard.lib")

// Helper function to convert ASCII hex string to bytes
std::vector<BYTE> hexStringToBytes(const std::string &hex) {
  std::vector<BYTE> bytes;
  for (size_t i = 0; i < hex.length(); i += 2) {
    if (i + 1 >= hex.length())
      break;
    std::string byteString = hex.substr(i, 2);
    BYTE byte = (BYTE)strtol(byteString.c_str(), NULL, 16);
    bytes.push_back(byte);
  }
  return bytes;
}

// Helper function to convert bytes to hex string
std::string bytesToHexString(const std::vector<BYTE> &data) {
  std::stringstream ss;
  for (const auto &byte : data) {
    ss << std::hex << std::setw(2) << std::setfill('0') << (int)byte;
  }
  return ss.str();
}

// Mimic Clh::AddLen functionality to add AID data to command
std::vector<BYTE> addLenToCommand(const std::string &apduString,
                                  const std::string &aid) {
  std::vector<BYTE> result = hexStringToBytes(apduString);
  std::vector<BYTE> aidBytes = hexStringToBytes(aid);

  // Add length byte
  result.push_back((BYTE)aidBytes.size());

  // Add AID data
  for (const auto &byte : aidBytes) {
    result.push_back(byte);
  }

  return result;
}

/**
 * Transmits an APDU to the card and returns all response data including
 * SW1/SW2.
 */
std::vector<BYTE> transmitAPDU(SCARDHANDLE cardHandle,
                               const std::vector<BYTE> &apduCmd,
                               bool printDebug = false) {
  std::vector<BYTE> response(256, 0);
  DWORD responseLen = static_cast<DWORD>(response.size());

  if (printDebug) {
    std::cout << "Sending APDU: ";
    for (const auto &byte : apduCmd) {
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte
                << " ";
    }
    std::cout << std::endl;
  }

  LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, apduCmd.data(),
                              (DWORD)apduCmd.size(), nullptr, response.data(),
                              &responseLen);

  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Transmit failed. Error: 0x" << std::hex << status
              << std::endl;
    throw std::runtime_error("SCard transmission error");
  }

  // Resize to actual response length
  response.resize(responseLen);

  if (printDebug) {
    std::cout << "Response: ";
    for (const auto &byte : response) {
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)byte
                << " ";
    }
    std::cout << std::endl;

    if (responseLen >= 2) {
      std::cout << "Status: " << std::hex << std::setw(2) << std::setfill('0')
                << (int)response[responseLen - 2] << " " << std::setw(2)
                << std::setfill('0') << (int)response[responseLen - 1]
                << std::endl;
    }
  }

  return response;
}

/**
 * Read card dates using sequence from MAV4_MDAS_1::MDAS_Read_Dates
 */
bool readCardDates(SCARDHANDLE cardHandle, std::string &issueDate,
                   std::string &expiryDate, std::string &returnCode) {
  const bool DEBUG = true; // Enable to see detailed APDU information

  try {
    // Initial values
    returnCode = "ff";
    issueDate = "";
    expiryDate = "";

    // 1. SELECT Card Manager with proper AID
    // Prepare the SELECT COMMAND with AID
    std::string aidString = "a0000000183003010000000000000000";
    std::string selectCmd = "00a40400";
    std::vector<BYTE> selectApdu = addLenToCommand(selectCmd, aidString);

    // Send SELECT AID command
    std::vector<BYTE> response = transmitAPDU(cardHandle, selectApdu, DEBUG);
    if (response.size() < 2 || response[response.size() - 2] != 0x90 ||
        response[response.size() - 1] != 0x00) {
      std::cerr << "SELECT AID command failed with status: " << std::hex
                << (int)response[response.size() - 2] << " "
                << (int)response[response.size() - 1] << std::endl;
      return false;
    }

    // 2. SELECT MF command (3F00)
    std::vector<BYTE> selectMF = hexStringToBytes("00a40000023f00");
    response = transmitAPDU(cardHandle, selectMF, DEBUG);
    if (response.size() < 2 || response[response.size() - 2] != 0x90 ||
        response[response.size() - 1] != 0x00) {
      std::cerr << "SELECT MF command failed with status: " << std::hex
                << (int)response[response.size() - 2] << " "
                << (int)response[response.size() - 1] << std::endl;
      return false;
    }

    // 3. SELECT DF command (0300)
    std::vector<BYTE> selectDF = hexStringToBytes("00a40100020300");
    response = transmitAPDU(cardHandle, selectDF, DEBUG);
    if (response.size() < 2 || response[response.size() - 2] != 0x90 ||
        response[response.size() - 1] != 0x00) {
      std::cerr << "SELECT DF command failed with status: " << std::hex
                << (int)response[response.size() - 2] << " "
                << (int)response[response.size() - 1] << std::endl;
      return false;
    }

    // 4. SELECT EF command (0303)
    std::vector<BYTE> selectEF = hexStringToBytes("00a40200020303");
    response = transmitAPDU(cardHandle, selectEF, DEBUG);
    if (response.size() < 2 || response[response.size() - 2] != 0x90 ||
        response[response.size() - 1] != 0x00) {
      std::cerr << "SELECT EF command failed with status: " << std::hex
                << (int)response[response.size() - 2] << " "
                << (int)response[response.size() - 1] << std::endl;
      return false;
    }

    // Initialize variables for READ BINARY loop
    std::string p1p2 = "0000"; // Initial offset for READ BINARY
    std::string cardData = ""; // Accumulated card data
    std::string res = "";      // Last result status
    std::string tres1 = "";    // Temporary result status values
    std::string tres2 = "";
    bool done = false;

    // 5. READ BINARY loop
    while (!done) {
      // Build READ BINARY command: 00 B0 [P1] [P2] F8
      std::string readCmd = "00b0" + p1p2 + "f8";
      std::vector<BYTE> readBinary = hexStringToBytes(readCmd);

      // Send READ BINARY command
      response = transmitAPDU(cardHandle, readBinary, DEBUG);

      // Get SW1 and SW2 (status words)
      BYTE sw1 = response[response.size() - 2];
      BYTE sw2 = response[response.size() - 1];

      // Format status as hex string
      std::stringstream ss;
      ss << std::hex << std::setw(2) << std::setfill('0') << (int)sw1
         << std::setw(2) << std::setfill('0') << (int)sw2;
      res = ss.str();

      // Extract first 2 chars of status for tres1
      tres1 = res.substr(0, 2);
      // Get whole response without SW1/SW2
      std::vector<BYTE> dataBytes(response.begin(), response.end() - 2);
      std::string dataResponse = bytesToHexString(dataBytes);

      // Append response data
      cardData += dataResponse;

      // Check if we got a success status (9000)
      if (res == "9000") {
        // Increment P1P2 by 003E (using Clh::Add functionality)
        unsigned int p1p2Int = std::stoul(p1p2, nullptr, 16);
        p1p2Int += 0x3E;
        std::stringstream ssOffset;
        ssOffset << std::hex << std::setw(4) << std::setfill('0') << p1p2Int;
        p1p2 = ssOffset.str();
      }
      // Check if we got 6C (wrong Le)
      else if (tres1 == "6c") {
        // Use SW2 as Le (length) in a new command
        std::stringstream ssLe;
        ssLe << std::hex << std::setw(2) << std::setfill('0') << (int)sw2;
        tres2 = ssLe.str();

        // Create new command with SW2 as Le
        std::string newReadCmd = "00b0" + p1p2 + tres2;
        std::vector<BYTE> newReadBinary = hexStringToBytes(newReadCmd);

        // Send corrected READ BINARY command
        response = transmitAPDU(cardHandle, newReadBinary, DEBUG);

        // Extract response data without SW1/SW2
        std::vector<BYTE> newDataBytes(response.begin(), response.end() - 2);
        std::string newDataResponse = bytesToHexString(newDataBytes);

        // Append response data
        cardData += newDataResponse;

        // Get new status
        sw1 = response[response.size() - 2];
        sw2 = response[response.size() - 1];
        ss.str("");
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)sw1
           << std::setw(2) << std::setfill('0') << (int)sw2;
        res = ss.str();
      }
      // Check if we got 6B00 (end of file)
      else if (res == "6b00") {
        // End of data reached
        done = true;
      } else {
        // Unexpected error
        std::cerr << "READ BINARY failed with status: " << res << std::endl;
        return false;
      }

      // Check if we've reached the end of the loop
      if (res != "9000") {
        done = true;
      }
    }

    if (DEBUG) {
      std::cout << "Complete card data: " << cardData << std::endl;
    }

    // Now manually find the tags B2 and B3 instead of parsing the TLV structure
    // Based on the response we saw, we need to directly extract the values

    // First look for tag B2 (issue date)
    size_t posB2 = cardData.find("b2");
    if (posB2 != std::string::npos && posB2 + 4 <= cardData.length()) {
      // Skip tag and length bytes
      size_t dataPos = posB2 + 4;
      // The length should be in the second position after B2
      std::string lenStr = cardData.substr(posB2 + 2, 2);
      int lenVal = 0;
      try {
        lenVal = std::stoi(lenStr, nullptr, 16);
        // Extract the value (2 chars per byte)
        if (dataPos + (lenVal * 2) <= cardData.length()) {
          issueDate = cardData.substr(dataPos, lenVal * 2);
          if (DEBUG) {
            std::cout << "Found issue date: " << issueDate << std::endl;
          }
        }
      } catch (const std::exception &e) {
        std::cerr << "Error parsing issue date length: " << e.what()
                  << std::endl;
        // Fall back to fixed extraction if the length parsing fails
        issueDate =
            cardData.substr(dataPos, 36); // Based on the observed pattern
        if (DEBUG) {
          std::cout << "Using fixed length for issue date: " << issueDate
                    << std::endl;
        }
      }
    }

    // Next look for tag B3 (expiry date)
    size_t posB3 = cardData.find("b3", posB2 + 1); // Start search after B2
    if (posB3 != std::string::npos && posB3 + 4 <= cardData.length()) {
      // Skip tag and length bytes
      size_t dataPos = posB3 + 4;
      // The length should be in the second position after B3
      std::string lenStr = cardData.substr(posB3 + 2, 2);
      int lenVal = 0;
      try {
        lenVal = std::stoi(lenStr, nullptr, 16);
        // Extract the value (2 chars per byte)
        if (dataPos + (lenVal * 2) <= cardData.length()) {
          expiryDate = cardData.substr(dataPos, lenVal * 2);
          if (DEBUG) {
            std::cout << "Found expiry date: " << expiryDate << std::endl;
          }
        }
      } catch (const std::exception &e) {
        std::cerr << "Error parsing expiry date length: " << e.what()
                  << std::endl;
        // Fall back to fixed extraction if the length parsing fails
        expiryDate =
            cardData.substr(dataPos, 36); // Based on the observed pattern
        if (DEBUG) {
          std::cout << "Using fixed length for expiry date: " << expiryDate
                    << std::endl;
        }
      }
    }

    // If we couldn't find the tags, use direct offsets from the observed data
    if (issueDate.empty() && cardData.length() >= 40) {
      issueDate = cardData.substr(4, 36); // Example offset based on response
      if (DEBUG) {
        std::cout << "Using direct offset for issue date: " << issueDate
                  << std::endl;
      }
    }

    if (expiryDate.empty() && cardData.length() >= 76) {
      expiryDate = cardData.substr(40, 36); // Example offset based on response
      if (DEBUG) {
        std::cout << "Using direct offset for expiry date: " << expiryDate
                  << std::endl;
      }
    }

    // Set return code to success
    returnCode = "00";
    return true;
  } catch (const std::exception &e) {
    std::cerr << "Exception in readCardDates: " << e.what() << std::endl;
    return false;
  }
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

  std::cout << "Successfully connected to reader: " << readers[0] << std::endl;
  return 0;
}

int main() {
  SCARDHANDLE cardHandle;
  SCARDCONTEXT context;

  // Try to connect to the card reader
  if (GetCardHandle(cardHandle, context) != 0) {
    std::cout << "Attempting to connect again in 1 second\n";
    Sleep(1000);
    if (GetCardHandle(cardHandle, context) != 0)
      return 1;
  }

  // Read card dates
  std::string issueDate, expiryDate, returnCode;
  bool success = false;

  try {
    success = readCardDates(cardHandle, issueDate, expiryDate, returnCode);
    if (success) {
      std::cout << "\nCard date information:\n";
      std::cout << "Issue date: " << issueDate << std::endl;
      std::cout << "Expiry date: " << expiryDate << std::endl;
      std::cout << "Return code: " << returnCode << std::endl;
    } else {
      std::cerr << "Failed to read card dates. Return code: " << returnCode
                << std::endl;
    }
  } catch (const std::exception &e) {
    std::cerr << "Exception while reading card dates: " << e.what()
              << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  // Cleanup
  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return success ? EXIT_SUCCESS : EXIT_FAILURE;
}