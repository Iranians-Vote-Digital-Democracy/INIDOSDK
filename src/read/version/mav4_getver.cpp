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
#include <string>
#include <unordered_map>
#include <vector>
#include <windows.h>
#include <winscard.h>

#pragma comment(lib, "winscard.lib")

// APDU commands
static const BYTE SELECT_APP_APDU[] = {
    0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00, 0x00, 0x00, 0x18, 0x30,
    0x03, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const BYTE SELECT_MF_APDU[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
static const BYTE SELECT_DF_0600[] = {0x00, 0xA4, 0x01, 0x00, 0x02, 0x06, 0x00};
static const BYTE SELECT_EF_0601[] = {0x00, 0xA4, 0x02, 0x00, 0x02, 0x06, 0x01};
static const BYTE READ_BINARY_APDU[] = {
    0x00, 0xB0, 0x00, 0x00,
    0xF8}; // We'll modify P1P2 (offset) during execution

#define SW1_SUCCESS 0x90
#define SW2_SUCCESS 0x00

/**
 * Transmits an APDU to the card and returns the data (excluding SW1/SW2).
 * Exits on failure.
 */
std::vector<BYTE> transmitAPDU(SCARDHANDLE cardHandle, const BYTE *apduCmd,
                               size_t apduLen) {
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

  // Check the status bytes
  BYTE sw1 = response[responseLen - 2];
  BYTE sw2 = response[responseLen - 1];

  // Special case: 6C XX (wrong length, use XX) and 6B 00 (read beyond file)
  if (sw1 == 0x6C) {
    // Need to retry with the correct length
    BYTE newAPDU[5];
    memcpy(newAPDU, apduCmd, 4);
    newAPDU[4] = sw2; // Use the length from the card

    return transmitAPDU(cardHandle, newAPDU, 5);
  }

  if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
    std::cerr << "Error SW1: " << std::hex << (int)sw1 << ", SW2: " << (int)sw2
              << std::endl;

    // If we hit 6B00 (read beyond file), return empty response
    if (sw1 == 0x6B && sw2 == 0x00)
      return {};

    exit(EXIT_FAILURE);
  }

  // Resize to remove SW1/SW2
  response.resize(responseLen - 2);
  return response;
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
 * Read card version information using the GetVer_Gemalto protocol
 */
void readCardVersion(SCARDHANDLE cardHandle, std::string &persoKeyVer,
                     std::string &sod1KeyVer, std::string &sod2KeyVer,
                     std::string &pinAlgoVer, std::string &keyAlgoVer) {
  // Initial values
  persoKeyVer = "0000";
  sod1KeyVer = "0000";
  sod2KeyVer = "0000";
  pinAlgoVer = "0a";
  keyAlgoVer = "0a";

  // Select the card application
  transmitAPDU(cardHandle, SELECT_APP_APDU, sizeof(SELECT_APP_APDU));

  // Select MF
  transmitAPDU(cardHandle, SELECT_MF_APDU, sizeof(SELECT_MF_APDU));

  // Select DF 0600
  transmitAPDU(cardHandle, SELECT_DF_0600, sizeof(SELECT_DF_0600));

  // Select EF 0601
  transmitAPDU(cardHandle, SELECT_EF_0601, sizeof(SELECT_EF_0601));

  // Initialize counters and buffers
  std::vector<BYTE> tempData;
  std::vector<BYTE> efPersoData;
  BYTE offset[2] = {0x00, 0x00};

  // Read binary data in chunks
  bool done = false;
  while (!done) {
    // Create READ_BINARY command with current offset
    BYTE readBinaryCmd[5];
    memcpy(readBinaryCmd, READ_BINARY_APDU, 5);
    readBinaryCmd[2] = offset[0]; // P1 - high byte of offset
    readBinaryCmd[3] = offset[1]; // P2 - low byte of offset

    try {
      // Read data and append to our temporary buffer
      std::vector<BYTE> chunk = transmitAPDU(cardHandle, readBinaryCmd, 5);
      if (chunk.empty()) {
        done = true;
        continue;
      }

      // Append the chunk to our collected data
      tempData.insert(tempData.end(), chunk.begin(), chunk.end());

      // Increment offset for next read
      unsigned int currentOffset = (offset[0] << 8) | offset[1];
      currentOffset += chunk.size();
      offset[0] = (currentOffset >> 8) & 0xFF;
      offset[1] = currentOffset & 0xFF;

      // If we receive less than requested, we've reached the end
      if (chunk.size() < 0xF8) {
        done = true;
      }
    } catch (...) {
      // If we get an error (like 6B00), we're done
      done = true;
    }
  }

  // Now process the collected data to extract versions
  if (tempData.size() >= 2) {
    // In the real implementation, there would be more parsing here to populate:
    // persoKeyVer, sod1KeyVer, sod2KeyVer, pinAlgoVer, keyAlgoVer

    // Here we'll do a simplified extraction based on the original algorithm:
    // Looking for tag 'CC' for persoKeyVer
    for (size_t i = 0; i < tempData.size() - 1; i++) {
      if (tempData[i] == 0xCC) {
        if (i + 3 < tempData.size()) {
          char hexBuf[5];
          sprintf(hexBuf, "%02X%02X", tempData[i + 1], tempData[i + 2]);
          persoKeyVer = hexBuf;
        }
        break;
      }
    }

    // Looking for tag 'D5' for sod1KeyVer
    for (size_t i = 0; i < tempData.size() - 1; i++) {
      if (tempData[i] == 0xD5) {
        if (i + 3 < tempData.size()) {
          char hexBuf[5];
          sprintf(hexBuf, "%02X%02X", tempData[i + 1], tempData[i + 2]);
          sod1KeyVer = hexBuf;
        }
        break;
      }
    }

    // Looking for tag 'D6' for sod2KeyVer
    for (size_t i = 0; i < tempData.size() - 1; i++) {
      if (tempData[i] == 0xD6) {
        if (i + 3 < tempData.size()) {
          char hexBuf[5];
          sprintf(hexBuf, "%02X%02X", tempData[i + 1], tempData[i + 2]);
          sod2KeyVer = hexBuf;
        }
        break;
      }
    }

    // Looking for tag 'D7' for pinAlgoVer
    for (size_t i = 0; i < tempData.size() - 1; i++) {
      if (tempData[i] == 0xD7) {
        if (i + 2 < tempData.size()) {
          char hexBuf[3];
          sprintf(hexBuf, "%02X", tempData[i + 1]);
          pinAlgoVer = hexBuf;
        }
        break;
      }
    }
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

  // Read card version info
  std::string persoKeyVer, sod1KeyVer, sod2KeyVer, pinAlgoVer, keyAlgoVer,
      returnCode;
  try {
    readCardVersion(cardHandle, persoKeyVer, sod1KeyVer, sod2KeyVer, pinAlgoVer,
                    keyAlgoVer);
    returnCode = "00"; // Success
  } catch (...) {
    std::cerr << "Exception while reading card versions." << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    returnCode = "ff"; // Error
    return EXIT_FAILURE;
  }

  // Print results
  std::cout << "Card Version Information:" << std::endl;
  std::cout << "Perso Key Version: " << persoKeyVer << std::endl;
  std::cout << "SOD1 Key Version: " << sod1KeyVer << std::endl;
  std::cout << "SOD2 Key Version: " << sod2KeyVer << std::endl;
  std::cout << "PIN Algorithm Version: " << pinAlgoVer << std::endl;
  std::cout << "Key Algorithm Version: " << keyAlgoVer << std::endl;
  std::cout << "Return Code: " << returnCode << std::endl;

  // Cleanup
  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}