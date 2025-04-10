#include <algorithm>
#include <cctype>
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
  void *sendAPDU(void **response, const std::string &apdu, int context_id,
                 const std::string *expected_sw = nullptr);

  // Helper methods for data manipulation
  static std::string StringToLower(const std::string &input);
  static std::string Truncate(const char *context_buffer, int context_id,
                              const std::string &input, const std::string &from,
                              const std::string &to);
  static std::string Sub(const char *value1, const std::string &mode);
  static std::string Sub(const std::string &value1, const std::string &value2,
                         const std::string &mode);
  static std::string AddLen(const std::string &data, const std::string &prefix);
  static std::string GetLength(const std::string &mode);
  static std::string AddPadding(const char *context_buffer, int context_id,
                                const std::string &padding_char,
                                const std::string &input);

  // Main function we're implementing
  int64_t VerifyIDPIN(void **pin_ascii, void **status, void **try_counter,
                      void **return_code);
};

/**
 * Verifies the ID PIN against the card
 *
 * @param pin_ascii The PIN to verify in ASCII format
 * @param status Output parameter for the verification status
 * @param try_counter Output parameter for the number of remaining tries
 * @param return_code Output parameter for the return code
 * @return 0 on success
 */
int64_t MAV4_General_1::VerifyIDPIN(void **pin_ascii, void **status,
                                    void **try_counter, void **return_code) {
  // Set status flag to active
  status_flag = true;

  // Set the function name for logging
  function_name = "VerifyIDPIN";

  // Store the PIN in lowercase
  std::string lowercase_pin = StringToLower(*(std::string *)pin_ascii);
  parameters["@idpin_ascii"] = lowercase_pin;

  // Initialize return values
  parameters["%returncode"] = "ff";
  parameters["%status"] = "f3";
  parameters["%trycounter"] = "";

  // Step 1: Select the main application
  std::string aid = "a0000000183003010000000000000000";
  std::string select_apdu = "00a40400" + AddLen(aid, "ISO7816");
  std::string response;
  sendAPDU((void **)&response, select_apdu, 14);

  // Copy PIN to parameters for processing
  parameters["%pin"] = parameters["@idpin_ascii"];

  // Determine PIN length
  parameters["%length"] = GetLength("h");

  // If PIN length is not 8 bytes, pad it with zeros
  if (parameters["%length"] != "08") {
    parameters["%pin"] = AddPadding(log_buffer, 20, "00", parameters["%pin"]);
  }

  // Step 2: Select the EV PIN application for verification
  // First select Master File
  sendAPDU((void **)&response, "00a40000023f00", 24);

  // Then select the PIN directory
  sendAPDU((void **)&response, "00a40100020500", 26);

  // Step 3: Verify EV PIN
  // Create VERIFY command with the PIN value
  std::string verify_apdu = "0020000008" + parameters["%pin"];
  std::string expected_sw = "63,6983";
  sendAPDU((void **)&response, verify_apdu, 29, &expected_sw);

  // Process the response
  parameters["%sw"] = parameters["%lastresult"];

  // Check EV PIN verification result
  if (parameters["%sw"] == "9000") {
    // PIN verification succeeded
    parameters["%evpinstatus"] = "11";
    parameters["%evtrycounter"] = "03";
  } else if (parameters["%sw"] == "6983" || parameters["%sw"] == "63c0") {
    // PIN is blocked or no tries remain
    parameters["%evpinstatus"] = "f2";
    parameters["%evtrycounter"] = "00";
  } else {
    // Extract SW1 and SW2 components
    parameters["%sw1"] =
        Truncate(log_buffer, 36, parameters["%sw"], "00", "01");
    parameters["%sw2"] =
        Truncate(log_buffer, 37, parameters["%sw"], "01", "01");

    if (parameters["%sw1"] == "63") {
      // PIN verification failed but tries remain
      parameters["%evtrycounter"] = parameters["%sw2"];
      // Calculate remaining tries by subtracting from c0
      parameters["%evtrycounter"] = Sub(parameters["%sw2"], "c0", "h");
      parameters["%evpinstatus"] = "f1";
    }
  }

  // Step 4: Select the ID PIN application for verification
  // First select Master File
  sendAPDU((void **)&response, "00a40000023f00", 58);

  // Then select the PIN directory
  sendAPDU((void **)&response, "00a40100020200", 60);

  // Step 5: Verify ID PIN (MPCOS)
  // Create VERIFY command with the PIN value
  verify_apdu = "0020000008" + parameters["%pin"];
  expected_sw = "63,6983";
  sendAPDU((void **)&response, verify_apdu, 63, &expected_sw);

  // Process the response
  parameters["%sw"] = parameters["%lastresult"];

  // Check ID PIN verification result
  if (parameters["%sw"] == "9000") {
    // PIN verification succeeded
    parameters["%mpcostrycounter"] = "03";
    parameters["%idpinstatus"] = "11";
  } else if (parameters["%sw"] == "6983" || parameters["%sw"] == "63c0") {
    // PIN is blocked or no tries remain
    parameters["%mpcostrycounter"] = "00";
    parameters["%idpinstatus"] = "f2";
  } else {
    // Extract SW1 and SW2 components
    parameters["%sw1"] =
        Truncate(log_buffer, 69, parameters["%sw"], "00", "01");
    parameters["%sw2"] =
        Truncate(log_buffer, 70, parameters["%sw"], "01", "01");

    if (parameters["%sw1"] == "63") {
      // PIN verification failed but tries remain
      parameters["%mpcostrycounter"] = parameters["%sw2"];
      // Calculate remaining tries by subtracting from c0
      parameters["%mpcostrycounter"] = Sub(parameters["%sw2"], "c0", "h");
      parameters["%idpinstatus"] = "f1";
    }
  }

  // Step 6: Select the IAS application for verification
  aid = "a0000000180c000001634200";
  select_apdu = "00a40400" + AddLen(aid, "ICAO");
  sendAPDU((void **)&response, select_apdu, 91);

  // Copy PIN to IAS parameter
  parameters["%idpin"] = parameters["@idpin_ascii"];

  // Ensure PIN is properly formatted for IAS (must be 16 bytes)
  while (GetLength("h") != "10") {
    parameters["%idpin"] += "00";
  }

  // Step 7: Verify IAS PIN
  // Create VERIFY command with the PIN value
  verify_apdu = "0020008110" + parameters["%idpin"];
  expected_sw = "63,6983,6984";
  sendAPDU((void **)&response, verify_apdu, 104, &expected_sw);

  // Process the response
  parameters["%sw"] = parameters["%lastresult"];

  // Check IAS PIN verification result
  if (parameters["%sw"] == "6983" || parameters["%sw"] == "6984" ||
      parameters["%sw"] == "63c0") {
    // PIN is blocked or no tries remain
    parameters["%iastrycounter"] = "00";
    parameters["%iasstatus"] = "f2";
  } else {
    // Extract SW1 and SW2 components
    parameters["%sw1"] =
        Truncate(log_buffer, 112, parameters["%sw"], "00", "01");
    parameters["%sw2"] =
        Truncate(log_buffer, 113, parameters["%sw"], "01", "01");

    if (parameters["%sw1"] == "90") {
      // PIN verification succeeded
      parameters["%iastrycounter"] = "03";
      parameters["%iasstatus"] = "11";
    } else if (parameters["%sw1"] == "63") {
      // PIN verification failed but tries remain
      parameters["%iastrycounter"] = parameters["%sw2"];
      // Calculate remaining tries by subtracting from c0
      parameters["%iastrycounter"] = Sub(parameters["%sw2"], "c0", "h");
      parameters["%iasstatus"] = "f1";
    }
  }

  // Step 8: Determine which PIN status to use (precedence between EV and ID
  // PIN)
  parameters["%stat"] =
      Sub(parameters["%evpinstatus"], parameters["%idpinstatus"], "h");
  parameters["%stat"] =
      Truncate(log_buffer, 135, parameters["%stat"], "00", "01");

  if (parameters["%stat"] == "ff") {
    // EV PIN has precedence
    parameters["%mptrycounter"] = parameters["%evtrycounter"];
    parameters["%mpstatus"] = parameters["%evpinstatus"];
  } else {
    // ID PIN has precedence
    parameters["%mptrycounter"] = parameters["%mpcostrycounter"];
    parameters["%mpstatus"] = parameters["%idpinstatus"];
  }

  // Step 9: Determine final status (precedence between MP and IAS)
  parameters["%st"] =
      Sub(parameters["%iasstatus"], parameters["%mpstatus"], "h");
  parameters["%st"] = Truncate(log_buffer, 147, parameters["%st"], "00", "01");

  if (parameters["%st"] == "ff") {
    // IAS has precedence
    parameters["%trycounter"] = parameters["%iastrycounter"];
    parameters["%status"] = parameters["%iasstatus"];
  } else {
    // MP has precedence
    parameters["%trycounter"] = parameters["%mptrycounter"];
    parameters["%status"] = parameters["%mpstatus"];
  }

  // Set successful return code
  parameters["%returncode"] = "00";

  // Copy values to output parameters
  *(std::string *)status = parameters["%status"];
  *(std::string *)try_counter = parameters["%trycounter"];
  *(std::string *)return_code = parameters["%returncode"];

  // Mark function as finished
  function_name = "Finished";

  return 0;
}