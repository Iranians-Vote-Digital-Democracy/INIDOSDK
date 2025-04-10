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

// Each APDU as indicated in MAV4_General_1::ReadCSN_CRN
// 1) SELECT: "00a4040008a000000018434d00"
// 2) GET CPLC: "80ca9f7f2d"
// 3) GET Tag0101: "80ca010115"
static const BYTE APDU_SELECT[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00,
                                   0x00, 0x00, 0x18, 0x43, 0x4D, 0x00};
static const BYTE APDU_GET_CPLC[] = {0x80, 0xCA, 0x9F, 0x7F, 0x2D};
static const BYTE APDU_GET_0101[] = {0x80, 0xCA, 0x01, 0x01, 0x15};

#define SW1_SUCCESS 0x90
#define SW2_SUCCESS 0x00

/**
 * Sends an APDU and returns response data excluding SW1/SW2.
 * Exits on error.
 */
std::vector<BYTE> transmitAPDU(SCARDHANDLE cardHandle, const BYTE *apdu,
                               size_t apduLen) {
  std::vector<BYTE> response(256, 0);
  DWORD responseLen = static_cast<DWORD>(response.size());

  LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, apdu, (DWORD)apduLen,
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

  BYTE sw1 = response[responseLen - 2];
  BYTE sw2 = response[responseLen - 1];
  if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
    std::cerr << "Error SW1: 0x" << std::hex << (int)sw1 << ", SW2: 0x"
              << (int)sw2 << std::endl;
    exit(EXIT_FAILURE);
  }

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
 * Reads CSN and CRN using the commands and offsets from
 * MAV4_General_1::ReadCSN_CRN:
 *
 * 1) SELECT with APDU_SELECT
 * 2) GET CPLC with APDU_GET_CPLC
 *    - from response, extract offset=0x08, length=0x13 -> CSN
 * 3) GET Tag0101 with APDU_GET_0101
 *    - from response, extract offset=0x10, length=0x03 -> CRN
 */
void readCSN_CRN(SCARDHANDLE cardHandle, std::vector<BYTE> &csnOut,
                 std::vector<BYTE> &crnOut) {
  // (1) SELECT
  transmitAPDU(cardHandle, APDU_SELECT, sizeof(APDU_SELECT));

  // (2) GET CPLC
  auto cplcData =
      transmitAPDU(cardHandle, APDU_GET_CPLC, sizeof(APDU_GET_CPLC));
  csnOut = truncateData(cplcData, 0x08, 0x13); // offset=0x08, length=0x13

  // (3) GET Tag0101
  auto tag0101 = transmitAPDU(cardHandle, APDU_GET_0101, sizeof(APDU_GET_0101));
  crnOut = truncateData(tag0101, 0x10, 0x03); // offset=0x10, length=0x03
}

/**
 * Connect to a card and retrieve the handle.
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

  std::vector<BYTE> csn, crn;
  try {
    readCSN_CRN(cardHandle, csn, crn);
  } catch (...) {
    std::cerr << "Exception while reading CSN/CRN." << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  auto printHex = [&](const std::vector<BYTE> &data, const char *label) {
    std::cout << label << ": ";
    for (auto b : data)
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b
                << " ";
    std::cout << std::dec << std::endl;
  };

  printHex(csn, "CSN");
  printHex(crn, "CRN");

  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}
