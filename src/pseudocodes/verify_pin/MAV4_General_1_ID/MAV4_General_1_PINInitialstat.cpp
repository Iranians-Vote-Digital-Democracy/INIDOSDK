#include <memory>
#include <string>
#include <unordered_map>

/**
 * Structure representing the MAV4_General_1 class
 */
struct MAV4_General_1 {
  // Based on offsets observed in the code
  char buffer[104];                                        // 0-103
  char log_buffer[40];                                     // 104-143
  std::string function_name;                               // 144-?
  std::unordered_map<std::string, std::string> parameters; // At offset 184
  bool status_flag;                                        // At offset 1272

  // Helper methods for card operations
  void *sendAPDU(void **response, const std::string &apdu, int context_id);

  // Helper for truncating data
  static std::string Truncate(const char *context_buffer, int context_id,
                              const std::string &input, const std::string &from,
                              const std::string &to);

  // Main function we're implementing
  int64_t PINInitialstat(std::string *nmoc_pin_status,
                         std::string *sign_pin_status, void **id_pin_status,
                         void **return_code);
};

/**
 * Gets the initial status of all PINs (NMOC, Sign, ID)
 *
 * @param nmoc_pin_status Output parameter for NMOC PIN status
 * @param sign_pin_status Output parameter for Sign PIN status
 * @param id_pin_status Output parameter for ID PIN status
 * @param return_code Output parameter for return code
 * @return 0 on success
 */
int64_t MAV4_General_1::PINInitialstat(std::string *nmoc_pin_status,
                                       std::string *sign_pin_status,
                                       void **id_pin_status,
                                       void **return_code) {
  // Set status flag to active
  status_flag = true;

  // Set the function name for logging
  function_name = "PINInitialstat";

  // Initialize return code
  parameters["%returncode"] = "ff";

  // Step 1: Select the main application
  std::string *response = new std::string();
  void **responsePtr = reinterpret_cast<void **>(&response);
  sendAPDU(responsePtr, "00a4040010a0000000183003010000000000000000", 12);

  // Step 2: Select the Master File
  sendAPDU(responsePtr, "00a40000023f00", 15);

  // Step 3: Select the PIN status file
  sendAPDU(responsePtr, "00a40200020010", 17);

  // Step 4: Read sign PIN flag
  sendAPDU(responsePtr, "00b0000402", 20);
  parameters["%flag_signpin"] = *response;

  // Step 5: Read ID PIN flag
  sendAPDU(responsePtr, "00b0000502", 22);
  parameters["%flag_idpin"] = *response;

  // Step 6: Read NMOC PIN flag
  sendAPDU(responsePtr, "00b0000702", 24);
  parameters["%flag_nmocpin"] = *response;

  // Process NMOC PIN flag - parse and extract specific part
  std::string extractedNmocPin = parameters["%flag_nmocpin"];
  parameters["%flag_nmocpin"] =
      Truncate(log_buffer, 25, extractedNmocPin, "00", "01");

  // Determine NMOC PIN status
  if (parameters["%flag_nmocpin"] != "02") {
    parameters["%nmocpinstatus"] = "0f"; // Not active
  } else {
    parameters["%nmocpinstatus"] = "01"; // Active
  }

  // Determine Sign PIN status
  if (parameters["%flag_signpin"] == "ac00") {
    parameters["%signpinstatus"] = "0f"; // Not active
  } else {
    parameters["%signpinstatus"] = "01"; // Active
  }

  // Determine ID PIN status
  if (parameters["%flag_idpin"] == "ac10") {
    parameters["%idpinstatus"] = "0f"; // Not active
  } else {
    parameters["%idpinstatus"] = "01"; // Active
  }

  // Set successful return code
  parameters["%returncode"] = "00";

  // Copy values to output parameters
  if (nmoc_pin_status != nullptr) {
    *nmoc_pin_status = parameters["%nmocpinstatus"];
  }

  if (sign_pin_status != nullptr) {
    *sign_pin_status = parameters["%signpinstatus"];
  }

  // Copy ID PIN status and return code to output pointers
  if (id_pin_status != nullptr) {
    *id_pin_status = new std::string(parameters["%idpinstatus"]);
  }

  if (return_code != nullptr) {
    *return_code = new std::string(parameters["%returncode"]);
  }

  // Cleanup
  delete response;

  // Mark function as finished
  function_name = "Finished";

  return 0;
}