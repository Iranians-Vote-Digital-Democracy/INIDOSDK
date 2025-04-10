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
#include <vector>
#include <windows.h>
#include <winscard.h>

#pragma comment(lib, "winscard.lib")

/**
 * New APDUs from the pseudocode.
 * These replace the old commands.
 */

// 1) 00A40400 + AID1 + 00
static const BYTE SELECT_AID_1[] = {
    0x00, 0xA4, 0x04, 0x00, // CLA=0x00, INS=0xA4 (SELECT), P1=0x04, P2=0x00
    0x10,                   // Lc = 16 bytes for the AID
    0x4D, 0x41, 0x54, 0x49, // 'M','A','T','I'
    0x52, 0x41, 0x4E, 0x20, // 'R','A','N',' '
    0x49, 0x44, 0x20, 0x43, // 'I','D',' ','C'
    0x41, 0x52, 0x44, 0x20, // 'A','R','D',' '
    0x00                    // Le (0x00 means no specific length requested)
};

// 2) 00A40400 + AID2 + 00
static const BYTE SELECT_AID_2[] = {0x00, 0xA4, 0x04, 0x00,
                                    0x0F, // Lc = 15 bytes
                                    0x39, 0x8D, 0xE5, 0xBA, 0xB4, 0x1E,
                                    0xC6, 0x76, 0xCA, 0xBD, 0xB5, 0x26,
                                    0xE5, 0x85, 0x71, 0x00};

// 3) 00A4030000
static const BYTE APDU_A4030000[] = {0x00, 0xA4, 0x03, 0x00, 0x00};

// 4) 00A4000002110000
static const BYTE APDU_A4000002110000[] = {0x00, 0xA4, 0x00, 0x00, // SELECT
                                           0x02, 0x11, 0x00, 0x00};

// 5) 00A4000002110300
static const BYTE APDU_A4000002110300[] = {0x00, 0xA4, 0x00, 0x00,
                                           0x02, 0x11, 0x03, 0x00};

// 6) 00B0000038
static const BYTE APDU_B0000038[] = {0x00, 0xB0, 0x00, 0x00, 0x38};

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
    std::cerr << "Transmit failed. Error: 0x" << std::hex << status
              << std::endl;
    exit(EXIT_FAILURE);
  }

  // Check we have at least 2 bytes for SW1/SW2
  if (responseLen < 2) {
    std::cerr << "Invalid response length: " << responseLen << std::endl;
    exit(EXIT_FAILURE);
  }

  // Check status bytes
  BYTE sw1 = response[responseLen - 2];
  BYTE sw2 = response[responseLen - 1];
  if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
    std::cerr << "APDU error SW1: " << std::hex << (int)sw1
              << ", SW2: " << (int)sw2 << std::endl;
    exit(EXIT_FAILURE);
  }

  // Remove SW1/SW2
  response.resize(responseLen - 2);
  return response;
}

/**
 * Demonstration of how to use the new APDUs.
 * Adjust logic to match your requirements.
 */
void readMetaFEID(SCARDHANDLE cardHandle) {
  // First select AID 1
  transmitAPDU(cardHandle, SELECT_AID_1, sizeof(SELECT_AID_1));

  // Select AID 2
  transmitAPDU(cardHandle, SELECT_AID_2, sizeof(SELECT_AID_2));

  // 00A4030000
  transmitAPDU(cardHandle, APDU_A4030000, sizeof(APDU_A4030000));

  // 00A4000002110000
  transmitAPDU(cardHandle, APDU_A4000002110000, sizeof(APDU_A4000002110000));

  // 00A4000002110300
  transmitAPDU(cardHandle, APDU_A4000002110300, sizeof(APDU_A4000002110300));

  // 00B0000038
  auto responseData =
      transmitAPDU(cardHandle, APDU_B0000038, sizeof(APDU_B0000038));
  // responseData now contains the bytes from offset 0..0x38-1

  // Print the data in hex
  std::cout << "Meta FEID Data:" << std::endl;
  for (auto b : responseData)
    std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b << " ";
  std::cout << std::dec << std::endl;
}

/**
 * Helper function from your original code.
 */
int GetCardHandle(SCARDHANDLE &cardHandle, SCARDCONTEXT &context) {
  memset(&context, 0, sizeof(context));
  LONG status =
      SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Failed to establish context. Error: 0x" << std::hex << status
              << std::endl;
    return EXIT_FAILURE;
  }

  LPSTR readersStr = nullptr;
  DWORD readersLen = SCARD_AUTOALLOCATE;
  status = SCardListReadersA(context, nullptr, (LPSTR)&readersStr, &readersLen);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Failed to list readers. Error: 0x" << std::hex << status
              << std::endl;
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

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
    std::cout << "Attempting to connect again in 1 second\n";
    Sleep(1000);
    if (GetCardHandle(cardHandle, context) != 0)
      return 1;
  }

  // Instead of reading CSN/CRN, we call the new routine that matches the
  // pseudocode logic.
  try {
    readMetaFEID(cardHandle);
  } catch (...) {
    std::cerr << "Exception while reading data." << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  // Cleanup
  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}
