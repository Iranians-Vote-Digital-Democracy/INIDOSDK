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

#define SW1_SUCCESS 0x90
#define SW2_SUCCESS 0x00

// APDU commands based on the disassembly
static const BYTE SELECT_IAS_APP[] = {0x00, 0xA4, 0x04, 0x00, 0x0C, 0xA0,
                                      0x00, 0x00, 0x00, 0x18, 0x0C, 0x00,
                                      0x00, 0x01, 0x63, 0x42, 0x00};
static const BYTE SELECT_CARD_MANAGER[] = {0x00, 0xA4, 0x04, 0x00, 0x08,
                                           0xA0, 0x00, 0x00, 0x00, 0x18,
                                           0x43, 0x4D, 0x00};
static const BYTE READ_CPLC[] = {0x80, 0xCA, 0x9F, 0x7F, 0x2D};
static const BYTE SELECT_MASTER_FILE[] = {0x00, 0xA4, 0x00, 0x00,
                                          0x02, 0x3F, 0x00};
static const BYTE SELECT_DF_50[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x50, 0x00};
static const BYTE SELECT_EF_5040[] = {0x00, 0xA4, 0x02, 0x0C, 0x02, 0x50, 0x40};
static const BYTE SELECT_MASTER_FILE_P2[] = {0x00, 0xA4, 0x00, 0x0C,
                                             0x02, 0x3F, 0x00};
static const BYTE SELECT_DF_50_P2[] = {0x00, 0xA4, 0x00, 0x0C,
                                       0x02, 0x50, 0x00};
static const BYTE SELECT_EF_5040_P2[] = {0x00, 0xA4, 0x02, 0x0C,
                                         0x02, 0x50, 0x40};
static const BYTE SELECT_EF_0303[] = {0x00, 0xA4, 0x02, 0x0C, 0x02, 0x03, 0x03};

// Utility to hold the APDU response plus the raw SW1/SW2
struct ApduResult {
  std::vector<BYTE> data;
  BYTE sw1;
  BYTE sw2;
};

ApduResult transmitAPDU(SCARDHANDLE cardHandle, const BYTE *apduCmd,
                        size_t apduLen) {
  std::vector<BYTE> response(256, 0);
  DWORD responseLen = (DWORD)response.size();

  LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, apduCmd, (DWORD)apduLen,
                              nullptr, response.data(), &responseLen);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Transmit failed. Error: 0x" << std::hex << status
              << std::endl;
    exit(EXIT_FAILURE);
  }

  if (responseLen < 2) {
    std::cerr << "Invalid response length: " << responseLen << std::endl;
    exit(EXIT_FAILURE);
  }

  // Separate out SW1/SW2 from the returned data
  BYTE sw1 = response[responseLen - 2];
  BYTE sw2 = response[responseLen - 1];
  response.resize(responseLen - 2);

  // Return everything so the caller can decide how to handle warnings
  ApduResult result;
  result.data = std::move(response);
  result.sw1 = sw1;
  result.sw2 = sw2;
  return result;
}

/**
 * Selects the necessary files for reading the Auth Certificate.
 */
void selectAuthCertificateFiles(SCARDHANDLE cardHandle) {
  transmitAPDU(cardHandle, SELECT_IAS_APP, sizeof(SELECT_IAS_APP));
  transmitAPDU(cardHandle, SELECT_CARD_MANAGER, sizeof(SELECT_CARD_MANAGER));
  transmitAPDU(cardHandle, READ_CPLC, sizeof(READ_CPLC));
  transmitAPDU(cardHandle, SELECT_IAS_APP, sizeof(SELECT_IAS_APP));
  transmitAPDU(cardHandle, SELECT_MASTER_FILE, sizeof(SELECT_MASTER_FILE));
  transmitAPDU(cardHandle, SELECT_DF_50, sizeof(SELECT_DF_50));
  transmitAPDU(cardHandle, SELECT_EF_5040, sizeof(SELECT_EF_5040));
  transmitAPDU(cardHandle, SELECT_MASTER_FILE_P2,
               sizeof(SELECT_MASTER_FILE_P2));
  transmitAPDU(cardHandle, SELECT_DF_50_P2, sizeof(SELECT_DF_50_P2));
  transmitAPDU(cardHandle, SELECT_EF_5040_P2, sizeof(SELECT_EF_5040_P2));
  transmitAPDU(cardHandle, SELECT_EF_0303, sizeof(SELECT_EF_0303));
}

// Example function that tries to interpret or handle different SW1/SW2
// statuses while still collecting data when possible.
std::vector<BYTE> readBinaryChunk(SCARDHANDLE cardHandle, int offset,
                                  int length) {
  BYTE readBinary[5];
  readBinary[0] = 0x00;                 // CLA
  readBinary[1] = 0xB0;                 // INS (READ BINARY)
  readBinary[2] = (offset >> 8) & 0xFF; // P1
  readBinary[3] = offset & 0xFF;        // P2
  readBinary[4] = (BYTE)length;         // Le

  auto result = transmitAPDU(cardHandle, readBinary, sizeof(readBinary));
  BYTE sw1 = result.sw1;
  BYTE sw2 = result.sw2;

  // If we get 0x9000, it's a perfect success
  if (sw1 == 0x90 && sw2 == 0x00) {
    return result.data; // all good
  }
  // If we get 0x62xx, it's a warning � we can keep the data but handle the
  // warning
  else if (sw1 == 0x62) {
    std::cerr << "Warning SW1=0x62, SW2=0x" << std::hex << (int)sw2
              << ". Partial data or other warning." << std::endl;
    // We'll still return whatever data the card gave us
    return result.data;
  }
  // If we want to handle 0x63, 0x6C, 0x6B00, 0x6D00 specially, do it here...
  // else if (sw1 == 0x63 || sw1 == 0x6C /* ... */) ...

  // Otherwise treat it as fatal
  std::cerr << "Unhandled error SW1=0x" << std::hex << (int)sw1 << ", SW2=0x"
            << (int)sw2 << std::endl;
  // Return empty or exit. Here, let's just return empty
  // so the reading loop can interpret it as "EOF or error."
  return {};
}

// You can keep the same certificate reading logic as before, only replacing
// references to "transmitAPDU" with "readBinaryChunk" so you can handle SW1/SW2
// more flexibly.
std::vector<BYTE> readAuthCertificate(SCARDHANDLE cardHandle) {
  // example, read first 2 bytes as potential length
  int offset = 0;
  auto firstChunk = readBinaryChunk(cardHandle, offset, 2);
  if (firstChunk.size() < 2) {
    // No data or partial -> handle gracefully
    std::cerr << "Not enough data to determine length." << std::endl;
    return {};
  }

  int totalSize = (firstChunk[0] << 8) | firstChunk[1];
  std::cout << "Indicated length: " << totalSize << std::endl;

  std::vector<BYTE> fullCertificate;
  fullCertificate.insert(fullCertificate.end(), firstChunk.begin(),
                         firstChunk.end());
  offset += 2;

  // read loop
  const int maxChunk = 0xFE;
  while ((int)fullCertificate.size() < totalSize) {
    int remaining = totalSize - (int)fullCertificate.size();
    int readSize = (remaining > maxChunk) ? maxChunk : remaining;

    auto chunk = readBinaryChunk(cardHandle, offset, readSize);
    if (chunk.empty()) {
      std::cerr << "No more data or an error occurred." << std::endl;
      break;
    }

    fullCertificate.insert(fullCertificate.end(), chunk.begin(), chunk.end());
    offset += (int)chunk.size();

    // If chunk < readSize, assume we hit EOF/warning
    if ((int)chunk.size() < readSize) {
      std::cerr << "Returned chunk smaller than requested. Possibly EOF."
                << std::endl;
      break;
    }
  }

  return fullCertificate;
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

  // (2) List readers@
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

  try {
    // (4) Perform the selects to get to the certificate EF
    selectAuthCertificateFiles(cardHandle);

    // (5) Read the certificate
    auto certificateData = readAuthCertificate(cardHandle);
    std::cout << "Certificate size read: " << certificateData.size() << " bytes"
              << std::endl;

    // (6) Print in hex, possibly truncated
    size_t displaySize =
        certificateData.size(); // (certificateData.size() < 128) ?
                                // certificateData.size() : 128;
    // std::cout << "Certificate (first " << displaySize << " bytes) in hex:\n
    // ";
    std::ios_base::fmtflags f(std::cout.flags());
    std::cout << std::hex << std::setfill('0');
    for (size_t i = 0; i < displaySize; i++) {
      std::cout << std::setw(2) << (int)certificateData[i] << " ";
      if ((i + 1) % 16 == 0)
        std::cout << "\n  ";
    }
    std::cout << std::dec << std::endl;
    std::cout.flags(f);

  } catch (...) {
    std::cerr << "Exception reading Auth Certificate." << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  // (7) Cleanup
  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}
