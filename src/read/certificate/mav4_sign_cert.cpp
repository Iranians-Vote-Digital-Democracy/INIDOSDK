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

// Translated APDU sequences seen in MAV4_General_1::ReadSign_Certificate
// We show them as hex strings here, which we'll convert in transmitAPDU().
static const char *APDU_1 = "00A4040008A000000018434D00";
static const char *APDU_2 = "80CA9F7F2D"; // Reads CPLC info
static const char *APDU_3 = "00A404000CA0000000180C000001634200";
static const char *APDU_4 = "00A40000023F00";
static const char *APDU_5 = "00A40000025100";
static const char *APDU_6 = "00A4020C025040";
static const char *APDU_7 = "00A4000C023F00";
static const char *APDU_8 = "00A4000C025100";
static const char *APDU_9 = "00A4020C025040"; // Often reselect EF

// Simple helper to convert a hex string like "00A4040008..." to bytes
std::vector<BYTE> hexStringToBytes(const char *hexString) {
  std::vector<BYTE> result;
  while (*hexString && *(hexString + 1)) {
    unsigned int byteVal = 0;
    sscanf(hexString, "%2x", &byteVal);
    result.push_back(static_cast<BYTE>(byteVal));
    hexString += 2;
  }
  return result;
}

struct ApduResult {
  std::vector<BYTE> data;
  BYTE sw1;
  BYTE sw2;
};

ApduResult transmitAPDU(SCARDHANDLE cardHandle, const char *apduHex) {
  // Convert the hex string to raw bytes
  std::vector<BYTE> apduCmd = hexStringToBytes(apduHex);

  std::vector<BYTE> response(1024, 0);
  DWORD responseLen = static_cast<DWORD>(response.size());

  LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, apduCmd.data(),
                              static_cast<DWORD>(apduCmd.size()), nullptr,
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
  // Construct "00 B0 [offsetHi] [offsetLo] [length]"
  BYTE readCmd[5];
  readCmd[0] = 0x00;
  readCmd[1] = 0xB0;
  readCmd[2] = (offset >> 8) & 0xFF;
  readCmd[3] = offset & 0xFF;
  readCmd[4] = static_cast<BYTE>(length);

  std::vector<BYTE> response(1024, 0);
  DWORD responseLen = static_cast<DWORD>(response.size());

  LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, readCmd, 5, nullptr,
                              response.data(), &responseLen);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Read chunk failed. Error: 0x" << std::hex << status
              << std::endl;
    exit(EXIT_FAILURE);
  }

  if (responseLen < 2) {
    std::cerr << "Invalid response length during read: " << responseLen
              << std::endl;
    return {};
  }

  BYTE sw1 = response[responseLen - 2];
  BYTE sw2 = response[responseLen - 1];
  response.resize(responseLen - 2);

  // 0x9000 means success
  if (sw1 == 0x90 && sw2 == 0x00) {
    return response;
  }
  // Some cards might return 62xx as a warning, so we keep the data
  if (sw1 == 0x62) {
    return response;
  }

  // Otherwise we treat it as error and stop
  std::cerr << "Error SW1=0x" << std::hex << (int)sw1 << ", SW2=0x" << (int)sw2
            << std::endl;
  return {};
}

std::vector<BYTE> readSignCertificate(SCARDHANDLE cardHandle) {
  // Execute the APDU commands in sequence
  transmitAPDU(cardHandle, APDU_1); // SELECT AID A000000018434D00
  transmitAPDU(cardHandle, APDU_2); // 80CA9F7F2D (reads CPLC info, optional)
  transmitAPDU(cardHandle, APDU_3); // SELECT AID A0000000180C000001634200
  transmitAPDU(cardHandle, APDU_4); // SELECT MF
  transmitAPDU(cardHandle, APDU_5); // SELECT DF 51?
  transmitAPDU(cardHandle, APDU_6); // SELECT EF 5040
  transmitAPDU(cardHandle, APDU_7); // A4 3F00 with P1=0C
  transmitAPDU(cardHandle, APDU_8); // A4 5100 with P1=0C
  transmitAPDU(cardHandle, APDU_9); // A4 5040 with P1=02, P2=0C

  // Now read from the EF in chunks
  // We can assume chunk size 0x100
  std::vector<BYTE> fullData;
  const int chunkSize = 0x100;
  int offset = 0;

  while (true) {
    std::vector<BYTE> chunk = readBinaryChunk(cardHandle, offset, chunkSize);
    if (chunk.empty()) {
      break;
    }
    fullData.insert(fullData.end(), chunk.begin(), chunk.end());
    offset += static_cast<int>(chunk.size());

    // If we got less than chunkSize, we assume no more data
    if ((int)chunk.size() < chunkSize) {
      break;
    }
  }
  return fullData;
}

int main() {
  SCARDCONTEXT context;
  SCARDHANDLE cardHandle;

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

  try {
    std::vector<BYTE> signCert = readSignCertificate(cardHandle);
    std::cout << "Sign Certificate size: " << signCert.size() << " bytes\n\n";
    std::cout << "Data in hex:\n";
    std::ios_base::fmtflags f(std::cout.flags());
    std::cout << std::hex << std::setfill('0');

    for (size_t i = 0; i < signCert.size(); i++) {
      std::cout << std::setw(2) << static_cast<int>(signCert[i]) << " ";
      if ((i + 1) % 16 == 0)
        std::cout << "\n";
    }
    std::cout << std::dec << std::endl;
    std::cout.flags(f);
  } catch (...) {
    std::cerr << "Exception while reading the certificate." << std::endl;
  }

  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}
