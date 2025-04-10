#include <iomanip>
#include <iostream>
#include <string>
#include <vector>
#include <windows.h>
#include <winscard.h>

#pragma comment(lib, "winscard.lib")

// Import helper functions from get_uid_working.cpp
SCARDCONTEXT initializeContext();
std::vector<std::string> listReaders(SCARDCONTEXT context);
SCARDHANDLE connectToReader(SCARDCONTEXT context,
                            const std::string &readerName);

// Import the MAV4_General_1 class
#include "MAV4_General_1_PINInitialstat.cpp"

int main() {
  // Initialize the card context and connect to the reader
  SCARDCONTEXT context = initializeContext();
  auto readers = listReaders(context);

  if (readers.empty()) {
    std::cerr << "No readers available." << std::endl;
    SCardReleaseContext(context);
    return EXIT_FAILURE;
  }

  std::cout << "Available readers:" << std::endl;
  for (size_t i = 0; i < readers.size(); ++i) {
    std::cout << i << ": " << readers[i] << std::endl;
  }

  // Allow user to select a reader if multiple are available
  size_t readerIndex = 0;
  if (readers.size() > 1) {
    std::cout << "Select reader index (0-" << readers.size() - 1 << "): ";
    std::cin >> readerIndex;
    if (readerIndex >= readers.size()) {
      readerIndex = 0;
      std::cout << "Invalid selection. Using first reader." << std::endl;
    }
  }

  // Connect to the selected reader
  SCARDHANDLE cardHandle = connectToReader(context, readers[readerIndex]);
  std::cout << "Successfully connected to reader: " << readers[readerIndex]
            << std::endl;

  // Instantiate the MAV4_General_1 class
  MAV4_General_1 mav4;

  // Prepare input/output parameters for PINInitialstat
  std::string nmoc_pin_status;
  std::string sign_pin_status;
  std::string id_pin_status;
  std::string return_code;

  void *id_pin_status_ptr = &id_pin_status;
  void *return_code_ptr = &return_code;

  // Call the PINInitialstat function
  std::cout << "Requesting PIN status information..." << std::endl;
  int64_t result = mav4.PINInitialstat(&nmoc_pin_status, &sign_pin_status,
                                       &id_pin_status_ptr, &return_code_ptr);

  // Check the result and print the output parameters
  if (result == 0) {
    std::cout << "\n======= PIN Status Information =======\n" << std::endl;
    std::cout << "NMOC PIN Status: " << nmoc_pin_status << " ("
              << (nmoc_pin_status == "01" ? "Active" : "Not Active") << ")"
              << std::endl;

    std::cout << "Sign PIN Status: " << sign_pin_status << " ("
              << (sign_pin_status == "01" ? "Active" : "Not Active") << ")"
              << std::endl;

    std::cout << "ID PIN Status: " << id_pin_status << " ("
              << (id_pin_status == "01" ? "Active" : "Not Active") << ")"
              << std::endl;

    std::cout << "Return Code: " << return_code << " ("
              << (return_code == "00" ? "Success" : "Error") << ")"
              << std::endl;

    std::cout << "\n======================================\n" << std::endl;
  } else {
    std::cerr << "PINInitialstat failed with error code: " << result
              << std::endl;
  }

  // Disconnect and release resources
  std::cout << "Disconnecting from card reader..." << std::endl;
  SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
  SCardReleaseContext(context);
  std::cout << "Disconnected successfully." << std::endl;

  return EXIT_SUCCESS;
}
