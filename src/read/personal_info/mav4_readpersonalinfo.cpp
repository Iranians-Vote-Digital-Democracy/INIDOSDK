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

// Define the SCARD IO request structures externally since there's confusion
// with the constants
// static SCARD_IO_REQUEST g_rgSCardT0Pci = { 1, 8 };
// static SCARD_IO_REQUEST g_rgSCardT1Pci = { 2, 8 };
// static SCARD_IO_REQUEST g_rgSCardRawPci = { 3, 8 };

// Pointer to the active protocol request structure
LPCSCARD_IO_REQUEST g_pioSendPci = NULL;

// APDU commands from MAV4_General_1::Read_PersonalInfo1
static const BYTE SELECT_APPLET[] = {0x00, 0xA4, 0x04, 0x00, 0x10, 0xA0, 0x00,
                                     0x00, 0x00, 0x18, 0x30, 0x03, 0x01, 0x00,
                                     0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static const BYTE SELECT_MF[] = {0x00, 0xA4, 0x00, 0x00, 0x02, 0x3F, 0x00};
static const BYTE SELECT_DF1[] = {0x00, 0xA4, 0x01, 0x00, 0x02, 0x02, 0x00};
static const BYTE SELECT_DF2[] = {0x00, 0xA4, 0x02, 0x00, 0x02, 0x02, 0x01};

#define SW1_SUCCESS 0x90
#define SW2_SUCCESS 0x00

/**
 * Transmits an APDU to the card and returns the data.
 */
std::vector<BYTE> transmitAPDU(SCARDHANDLE cardHandle, const BYTE *apduCmd,
                               size_t apduLen) {
  std::vector<BYTE> response(256, 0);
  DWORD responseLen = static_cast<DWORD>(response.size());

  // Debug: Print the APDU command
  std::cout << "Sending APDU: ";
  for (size_t i = 0; i < apduLen; i++) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)apduCmd[i] << " ";
  }
  std::cout << std::endl;

  // Use a simpler approach with direct PC/SC call
  LONG status = SCardTransmit(cardHandle,      // Card handle
                              g_pioSendPci,    // Protocol control info
                              apduCmd,         // APDU command
                              (DWORD)apduLen,  // APDU command length
                              NULL,            // No PCI expected on response
                              response.data(), // Where to put response
                              &responseLen     // Length of response
  );

  if (status != SCARD_S_SUCCESS) {
    std::cerr << "Transmit failed. Error: 0x" << std::hex << status
              << std::endl;

    // Additional error handling
    switch (status) {
    case SCARD_E_INVALID_HANDLE:
      std::cerr << "Invalid handle. The handle is not valid." << std::endl;
      break;
    case SCARD_E_INVALID_VALUE:
      std::cerr << "Invalid value. One or more parameters are invalid."
                << std::endl;
      break;
    case SCARD_E_NOT_TRANSACTED:
      std::cerr << "Not transacted. An attempt was made to end a transaction "
                   "that is not currently active."
                << std::endl;
      break;
    case SCARD_E_PROTO_MISMATCH:
      std::cerr << "Protocol mismatch. The requested protocol is not supported."
                << std::endl;
      break;
    case SCARD_E_READER_UNAVAILABLE:
      std::cerr << "Reader unavailable. The reader has been removed."
                << std::endl;
      break;
    case SCARD_F_COMM_ERROR:
      std::cerr << "Communication error. An internal communications error has "
                   "been detected."
                << std::endl;
      break;
    default:
      std::cerr << "Unknown error." << std::endl;
    }

    // Instead of exiting, return empty response
    return std::vector<BYTE>();
  }

  // Check we have enough bytes
  if (responseLen < 2) {
    std::cerr << "Invalid response length: " << responseLen << std::endl;
    return std::vector<BYTE>();
  }

  // Debug: Print the response
  std::cout << "Response (" << responseLen << " bytes): ";
  for (DWORD i = 0; i < responseLen; i++) {
    std::cout << std::hex << std::setw(2) << std::setfill('0')
              << (int)response[i] << " ";
  }
  std::cout << std::endl;

  // Resize to include only the actual response
  response.resize(responseLen);
  return response;
}

/**
 * Converts a vector of bytes to a hex string
 */
std::string bytesToHexString(const std::vector<BYTE> &data,
                             bool includeStatusBytes = true) {
  if (data.empty())
    return "";

  size_t limit = data.size();
  if (!includeStatusBytes && limit >= 2) {
    limit -= 2; // Exclude the status bytes
  }

  std::stringstream ss;
  for (size_t i = 0; i < limit; i++) {
    ss << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(data[i]);
  }
  return ss.str();
}

/**
 * Read personal data from the card following the logic in
 * MAV4_General_1::Read_PersonalInfo1
 */
std::string readPersonalData(SCARDHANDLE cardHandle) {
  std::unordered_map<std::string, std::string> variables;
  variables["%returncode"] = "ff";
  variables["%personal_data1"] = "";

  // Try with a reset first
  DWORD dwAP = 0;
  LONG status = SCardReconnect(cardHandle, SCARD_SHARE_SHARED,
                               SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
                               SCARD_RESET_CARD, &dwAP);
  if (status == SCARD_S_SUCCESS) {
    std::cout << "Card reset successful, new protocol: "
              << (dwAP == SCARD_PROTOCOL_T0
                      ? "T0"
                      : (dwAP == SCARD_PROTOCOL_T1 ? "T1" : "Unknown"))
              << std::endl;

    // Set the protocol control structure
    if (dwAP == SCARD_PROTOCOL_T0)
      g_pioSendPci = &g_rgSCardT0Pci;
    else if (dwAP == SCARD_PROTOCOL_T1)
      g_pioSendPci = &g_rgSCardT1Pci;
    else {
      std::cerr << "Unsupported protocol" << std::endl;
      return "";
    }
  } else {
    std::cerr << "Card reset failed, error: 0x" << std::hex << status
              << std::endl;
    return "";
  }

  try {
    // Debug output
    std::cout << "Selecting applet..." << std::endl;

    // 1. Select Applet
    auto response =
        transmitAPDU(cardHandle, SELECT_APPLET, sizeof(SELECT_APPLET));
    if (response.empty()) {
      std::cerr << "Failed to select applet" << std::endl;
      return "";
    }

    BYTE sw1 = response[response.size() - 2];
    BYTE sw2 = response[response.size() - 1];

    // Check if select applet was successful
    if (sw1 != 0x90 || sw2 != 0x00) {
      std::cerr << "Select applet failed: SW1=" << std::hex << (int)sw1
                << " SW2=" << (int)sw2 << std::endl;

      // Try direct reading without selection
      std::cout << "Trying direct reading of personal data..." << std::endl;
    } else {
      // 2. Select MF
      std::cout << "Selecting MF..." << std::endl;
      response = transmitAPDU(cardHandle, SELECT_MF, sizeof(SELECT_MF));
      if (response.empty()) {
        std::cerr << "Failed to select MF" << std::endl;
        return "";
      }

      // 3. Select DF1
      std::cout << "Selecting DF1..." << std::endl;
      response = transmitAPDU(cardHandle, SELECT_DF1, sizeof(SELECT_DF1));
      if (response.empty()) {
        std::cerr << "Failed to select DF1" << std::endl;
        return "";
      }

      // 4. Select DF2
      std::cout << "Selecting DF2..." << std::endl;
      response = transmitAPDU(cardHandle, SELECT_DF2, sizeof(SELECT_DF2));
      if (response.empty()) {
        std::cerr << "Failed to select DF2" << std::endl;
        return "";
      }
    }

    // Set initial P1P2 values
    variables["%p1p2"] = "0000";
    variables["%d"] = "00";
    variables["%temp"] = "";

    // Main loop mimicking the do-while loop in the original function
    bool continue_loop = true;
    int iteration = 0;
    while (continue_loop && iteration < 10) { // Add iteration limit for safety
      iteration++;

      // Prepare the READ PERSONAL DATA command with current P1P2
      std::string p1p2Value = variables["%p1p2"];
      std::cout << "Iteration " << iteration << ", P1P2=" << p1p2Value
                << std::endl;

      // Build a READ command with current P1P2 values
      std::vector<BYTE> readCmd = {0x00, 0xB0};

      // Convert P1P2 from hex string to bytes
      if (p1p2Value.length() >= 4) {
        BYTE p1 = static_cast<BYTE>(
            strtol(p1p2Value.substr(0, 2).c_str(), nullptr, 16));
        BYTE p2 = static_cast<BYTE>(
            strtol(p1p2Value.substr(2, 2).c_str(), nullptr, 16));
        readCmd.push_back(p1);
        readCmd.push_back(p2);
        readCmd.push_back(0xF4); // Le byte from original command
      } else {
        // Default if P1P2 is not valid
        readCmd.push_back(0x00);
        readCmd.push_back(0x00);
        readCmd.push_back(0xF4);
      }

      // Send the READ command
      response = transmitAPDU(cardHandle, readCmd.data(), readCmd.size());
      if (response.empty()) {
        std::cerr << "Failed to read data with P1P2=" << p1p2Value << std::endl;
        break;
      }

      // Get the response status (last 2 bytes)
      BYTE sw1 = response[response.size() - 2];
      BYTE sw2 = response[response.size() - 1];

      char swBuffer[5];
      sprintf(swBuffer, "%02x%02x", sw1, sw2);
      std::string statusHex = swBuffer;
      variables["%res"] = statusHex;

      // Extract actual data (remove SW1/SW2)
      std::vector<BYTE> actualData(response.begin(), response.end() - 2);
      variables["%outi"] = bytesToHexString(actualData, false);
      std::cout << "Response data: " << variables["%outi"] << std::endl;

      // Update %temp with %outi
      variables["%temp"] += variables["%outi"];

      // Calculate new P1P2 value (adding 0x3D to current P1P2)
      // This corresponds to the Clh::Add(...) call in the original function
      unsigned int currentP1P2 = strtoul(p1p2Value.c_str(), nullptr, 16);
      unsigned int newP1P2 = currentP1P2 + 0x3D;
      char newP1P2Buffer[5];
      sprintf(newP1P2Buffer, "%04x", newP1P2);
      variables["%p1p2"] = newP1P2Buffer;

      // Check if status indicates we should stop
      if (sw1 == 0x6C) {
        std::cout << "Got 6C response, breaking loop" << std::endl;
        break;
      }

      if ((sw1 == 0x6B && sw2 == 0x00) || (sw1 != 0x90 || sw2 != 0x00)) {
        std::cout << "Got non-success response " << std::hex << (int)sw1
                  << (int)sw2 << ", breaking loop" << std::endl;
        break;
      }
    }

    // Update personal_data1 with the collected data
    variables["%personal_data1"] = variables["%temp"];
    variables["%returncode"] = "00";

    return variables["%personal_data1"];
  } catch (const std::exception &e) {
    std::cerr << "Exception: " << e.what() << std::endl;
    return "";
  } catch (...) {
    std::cerr << "Unknown exception" << std::endl;
    return "";
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

  // Set protocol control info based on active protocol
  if (activeProtocol == SCARD_PROTOCOL_T0)
    g_pioSendPci = &g_rgSCardT0Pci;
  else if (activeProtocol == SCARD_PROTOCOL_T1)
    g_pioSendPci = &g_rgSCardT1Pci;
  else {
    std::cerr << "Unsupported protocol" << std::endl;
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  // Debug message
  std::cout << "Successfully connected to reader: " << readers[0] << std::endl;
  std::cout << "Active protocol: "
            << (activeProtocol == SCARD_PROTOCOL_T0
                    ? "T0"
                    : (activeProtocol == SCARD_PROTOCOL_T1 ? "T1" : "Unknown"))
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

  // Read personal data
  std::string personalData = readPersonalData(cardHandle);

  if (personalData.empty()) {
    std::cerr << "Failed to read personal data" << std::endl;
  } else {
    // Print results
    std::cout << std::endl;
    std::cout << "Personal Data: " << personalData << std::endl;
  }

  // Cleanup
  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  return EXIT_SUCCESS;
}