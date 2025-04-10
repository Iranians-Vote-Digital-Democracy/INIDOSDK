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

// New APDU commands taken from the provided disassembly
static const BYTE SELECT_APP[] = {0x00, 0xA4, 0x04, 0x00, 0x0F, 0x50, 0x41,
                                  0x52, 0x44, 0x49, 0x53, 0x2C, 0x4D, 0x41,
                                  0x54, 0x49, 0x52, 0x41, 0x4E, 0x20};

static const BYTE SELECT_MF[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};

static const BYTE SELECT_DF_51[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x51, 0x00};

static const BYTE SELECT_EF_5040[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x50, 0x40};

// This extra select appears in the snippet (00A4020C020303).
static const BYTE SELECT_EXTRA[] = {0x00, 0xA4, 0x02, 0x0C, 0x02, 0x03, 0x03};

struct ApduResult {
  std::vector<BYTE> data;
  BYTE sw1;
  BYTE sw2;
};

ApduResult transmitAPDU(SCARDHANDLE cardHandle, const BYTE *apduCmd,
                        size_t apduLen) {
  std::vector<BYTE> response(256, 0);
  DWORD responseLen = static_cast<DWORD>(response.size());

  LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, apduCmd,
                              static_cast<DWORD>(apduLen), nullptr,
                              response.data(), &responseLen);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Transmit failed. Error: 0x" << std::hex << status
              << std::endl;
    exit(EXIT_FAILURE);
  }

  if (responseLen < 2) {
    std::cerr << "Invalid response length: " << responseLen << std::endl;
    exit(EXIT_FAILURE);
  }

  BYTE sw1 = response[responseLen - 2];
  BYTE sw2 = response[responseLen - 1];
  response.resize(responseLen - 2);

  ApduResult result;
  result.data = std::move(response);
  result.sw1 = sw1;
  result.sw2 = sw2;
  return result;
}

std::vector<BYTE> readBinaryChunk(SCARDHANDLE cardHandle, int offset,
                                  int length) {
  BYTE readBinary[5];
  readBinary[0] = 0x00;
  readBinary[1] = 0xB0;
  readBinary[2] = (offset >> 8) & 0xFF;
  readBinary[3] = offset & 0xFF;
  readBinary[4] = static_cast<BYTE>(length);

  ApduResult result = transmitAPDU(cardHandle, readBinary, sizeof(readBinary));
  if (result.sw1 == 0x90 && result.sw2 == 0x00) {
    return result.data;
  } else if (result.sw1 == 0x62) {
    std::cerr << "Warning SW1=0x62, SW2=0x" << std::hex << (int)result.sw2
              << std::endl;
    return result.data;
  }

  std::cerr << "Error SW1=0x" << std::hex << (int)result.sw1 << ", SW2=0x"
            << (int)result.sw2 << std::endl;
  return {};
}

void selectAuthCertificateFiles(SCARDHANDLE cardHandle) {
  transmitAPDU(cardHandle, SELECT_APP, sizeof(SELECT_APP));
  transmitAPDU(cardHandle, SELECT_MF, sizeof(SELECT_MF));
  transmitAPDU(cardHandle, SELECT_DF_51, sizeof(SELECT_DF_51));
  transmitAPDU(cardHandle, SELECT_EF_5040, sizeof(SELECT_EF_5040));
  transmitAPDU(cardHandle, SELECT_EXTRA, sizeof(SELECT_EXTRA));
}

std::vector<BYTE> readAuthCertificate(SCARDHANDLE cardHandle) {
  // Updated chunk size: 0xF8 from the snippet
  const int chunkSize = 0xF8;
  std::vector<BYTE> fullData;
  int offset = 0;

  while (true) {
    std::vector<BYTE> chunk = readBinaryChunk(cardHandle, offset, chunkSize);
    if (chunk.empty()) {
      break;
    }
    fullData.insert(fullData.end(), chunk.begin(), chunk.end());
    offset += static_cast<int>(chunk.size());

    if (static_cast<int>(chunk.size()) < chunkSize) {
      break;
    }
  }

  return fullData;
}

int GetCardHandle(SCARDHANDLE &cardHandle, SCARDCONTEXT &context) {
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
  LPSTR current = readersStr;
  while (current && *current) {
    readers.push_back(current);
    current += strlen(current) + 1;
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
  SCARDCONTEXT context;
  SCARDHANDLE cardHandle;
  if (GetCardHandle(cardHandle, context) != 0) {
    Sleep(1000);
    if (GetCardHandle(cardHandle, context) != 0) {
      return 1;
    }
  }

  try {
    selectAuthCertificateFiles(cardHandle);

    std::vector<BYTE> certificateData = readAuthCertificate(cardHandle);

    std::cout << "Certificate size: " << certificateData.size() << " bytes\n\n";

    std::cout << "Certificate in hex:\n";
    std::ios_base::fmtflags f(std::cout.flags());
    std::cout << std::hex << std::setfill('0');

    for (size_t i = 0; i < certificateData.size(); i++) {
      std::cout << std::setw(2) << static_cast<int>(certificateData[i]) << " ";
      if ((i + 1) % 16 == 0)
        std::cout << "\n";
    }
    std::cout << std::dec << std::endl;
    std::cout.flags(f);
  } catch (...) {
    std::cerr << "Exception while reading the certificate." << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}
