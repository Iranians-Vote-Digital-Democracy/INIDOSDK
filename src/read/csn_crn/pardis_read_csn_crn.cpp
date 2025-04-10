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

// New APDU sequences
static const BYTE APDU_SELECT[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00,
                                   0x00, 0x00, 0x03, 0x00, 0x00, 0x00};
static const BYTE APDU_GET_CPLC_1[] = {0x80, 0xCA, 0x9F, 0x7F, 0x00};
static const BYTE APDU_GET_CPLC_2[] = {0x00, 0xC0, 0x00, 0x00, 0x2D};
static const BYTE APDU_GET_CSN[] = {0x90, 0x38, 0x00, 0x00, 0x0C};

// Status bytes
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
 * Replaces the old steps (SELECT + GET CPLC + GET Tag0101) with:
 * 1) SELECT using APDU_SELECT
 * 2) GET CPLC in two parts (APDU_GET_CPLC_1 then APDU_GET_CPLC_2),
 *    combine them into one buffer
 * 3) Extract offsets from the combined CPLC data to get CRN
 * 4) Send APDU_GET_CSN to retrieve CSN
 */
void readCSN_CRN(SCARDHANDLE cardHandle, std::vector<BYTE> &csnOut,
                 std::vector<BYTE> &crnOut) {
  // (1) SELECT
  transmitAPDU(cardHandle, APDU_SELECT, sizeof(APDU_SELECT));

  // (2) Get CPLC in two parts
  auto cplcPart1 =
      transmitAPDU(cardHandle, APDU_GET_CPLC_1, sizeof(APDU_GET_CPLC_1));
  auto cplcPart2 =
      transmitAPDU(cardHandle, APDU_GET_CPLC_2, sizeof(APDU_GET_CPLC_2));

  // Combine the two responses into cplcData
  std::vector<BYTE> cplcData;
  cplcData.insert(cplcData.end(), cplcPart1.begin(), cplcPart1.end());
  cplcData.insert(cplcData.end(), cplcPart2.begin(), cplcPart2.end());

  // For example, suppose we derive CRN from certain offsets in the combined
  // data Adjust these as needed per your card's data layout The second snippet
  // references multiple offsets, but we'll keep it simple here
  std::vector<BYTE> crnTemp1 = truncateData(cplcData, 24, 2); // partial CRN
  std::vector<BYTE> crnTemp2 = truncateData(cplcData, 37, 8); // partial CRN
  crnOut.insert(crnOut.end(), crnTemp1.begin(), crnTemp1.end());
  crnOut.insert(crnOut.end(), crnTemp2.begin(), crnTemp2.end());

  // (3) Retrieve CSN from a separate APDU
  // (In the second snippet, "90 38 00 00 0C" is used to read out something that
  // might map to CSN)
  auto csnData = transmitAPDU(cardHandle, APDU_GET_CSN, sizeof(APDU_GET_CSN));
  csnOut = csnData; // or truncate further if needed
}

/**
 * Connect to a card and get the handle.
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
    for (auto b : data) {
      std::cout << std::hex << std::setw(2) << std::setfill('0') << (int)b
                << " ";
    }
    std::cout << std::dec << std::endl;
  };

  printHex(csn, "CSN");
  printHex(crn, "CRN");

  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}
