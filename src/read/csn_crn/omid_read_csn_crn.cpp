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

// New APDU commands derived from OMID2_General_0::GetCID
static const BYTE APDU_SELECT[] = {0x00, 0xA4, 0x04, 0x00, 0x08, 0xA0, 0x00,
                                   0x00, 0x00, 0x00, 0x18, 0x43, 0x4D, 0x00};
static const BYTE APDU_0084[] = {0x00, 0x84, 0x00, 0x00, 0x10};
static const BYTE APDU_0088010000[] = {0x00, 0x88, 0x01, 0x00, 0x00};
static const BYTE APDU_00C0000020[] = {0x00, 0xC0, 0x00, 0x00, 0x20};

#define SW1_SUCCESS 0x90
#define SW2_SUCCESS 0x00

std::vector<BYTE> transmitAPDU(SCARDHANDLE cardHandle, const BYTE *apdu,
                               size_t apduLen) {
  std::vector<BYTE> response(256, 0);
  DWORD responseLen = (DWORD)response.size();

  LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, apdu, (DWORD)apduLen,
                              nullptr, response.data(), &responseLen);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Transmit error: 0x" << std::hex << status << std::endl;
    exit(EXIT_FAILURE);
  }

  if (responseLen < 2) {
    std::cerr << "Response too short: " << responseLen << std::endl;
    exit(EXIT_FAILURE);
  }

  BYTE sw1 = response[responseLen - 2];
  BYTE sw2 = response[responseLen - 1];
  if (sw1 != SW1_SUCCESS || sw2 != SW2_SUCCESS) {
    std::cerr << "SW1: 0x" << std::hex << (int)sw1 << " SW2: 0x" << (int)sw2
              << std::endl;
    exit(EXIT_FAILURE);
  }

  response.resize(responseLen - 2);
  return response;
}

std::vector<std::string> listReaders(SCARDCONTEXT context) {
  LPSTR readersStr = nullptr;
  DWORD readersLen = SCARD_AUTOALLOCATE;
  LONG status =
      SCardListReadersA(context, nullptr, (LPSTR)&readersStr, &readersLen);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "SCardListReadersA error: 0x" << std::hex << status
              << std::endl;
    exit(EXIT_FAILURE);
  }

  std::vector<std::string> readers;
  if (readersStr) {
    LPSTR current = readersStr;
    while (*current) {
      readers.push_back(current);
      current += strlen(current) + 1;
    }
    SCardFreeMemory(context, readersStr);
  }

  if (readers.empty()) {
    std::cerr << "No readers found." << std::endl;
    exit(EXIT_FAILURE);
  }
  return readers;
}

SCARDHANDLE connectToCard(SCARDCONTEXT context, const std::string &readerName) {
  SCARDHANDLE cardHandle;
  DWORD activeProtocol;
  LONG status = SCardConnectA(context, readerName.c_str(), SCARD_SHARE_SHARED,
                              SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                              &cardHandle, &activeProtocol);
  if (status != SCARD_S_SUCCESS) {
    std::cerr << "SCardConnectA error: 0x" << std::hex << status << std::endl;
    exit(EXIT_FAILURE);
  }
  return cardHandle;
}

void readCID(SCARDHANDLE cardHandle) {
  auto respSelect = transmitAPDU(cardHandle, APDU_SELECT, sizeof(APDU_SELECT));
  auto respNonce = transmitAPDU(cardHandle, APDU_0084, sizeof(APDU_0084));
  auto resp0088010000 =
      transmitAPDU(cardHandle, APDU_0088010000, sizeof(APDU_0088010000));
  auto resp00c0000020 =
      transmitAPDU(cardHandle, APDU_00C0000020, sizeof(APDU_00C0000020));

  std::cout << "SELECT Response:       " << respSelect.size() << " bytes"
            << std::endl;
  std::cout << "Nonce (0084000010):    " << respNonce.size() << " bytes"
            << std::endl;
  std::cout << "0088010000 Response:   " << resp0088010000.size() << " bytes"
            << std::endl;
  std::cout << "00c0000020 Response:   " << resp00c0000020.size() << " bytes"
            << std::endl;
}

int main() {
  SCARDCONTEXT context;
  if (SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context) !=
      SCARD_S_SUCCESS) {
    std::cerr << "Cannot establish context." << std::endl;
    return EXIT_FAILURE;
  }

  auto readers = listReaders(context);
  SCARDHANDLE cardHandle = connectToCard(context, readers[0]);

  try {
    readCID(cardHandle);
  } catch (...) {
    std::cerr << "Error during readCID." << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}
