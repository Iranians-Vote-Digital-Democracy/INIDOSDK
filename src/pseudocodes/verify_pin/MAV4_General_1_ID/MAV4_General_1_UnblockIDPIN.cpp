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
  static std::string *AppendTwoSourcesToBuffer(std::string *result,
                                               const std::string *base,
                                               const std::string &append);

  // Main function we're implementing
  int64_t UnblockIDPIN(std::string *idpuk_hex, std::string *new_idpin_hex,
                       std::string *idpuk_ascii, std::string *new_idpin_ascii,
                       void **idpuk_status, void **return_code);
};

/**
 * Unblocks the ID PIN using the PUK and sets a new PIN
 *
 * @param idpuk_hex The PUK in hexadecimal format
 * @param new_idpin_hex The new PIN in hexadecimal format
 * @param idpuk_ascii The PUK in ASCII format
 * @param new_idpin_ascii The new PIN in ASCII format
 * @param idpuk_status Output parameter for the status
 * @param return_code Output parameter for the return code
 * @return 0 on success
 */
int64_t MAV4_General_1::UnblockIDPIN(std::string *idpuk_hex,
                                     std::string *new_idpin_hex,
                                     std::string *idpuk_ascii,
                                     std::string *new_idpin_ascii,
                                     void **idpuk_status, void **return_code) {
  // Set status flag to active
  status_flag = true;

  // Set the function name for logging
  function_name = "UnblockIDPIN";

  // Store the input parameters in lowercase
  parameters["@idpuk_hex"] = StringToLower(*idpuk_hex);
  parameters["@newidpin_hex"] = StringToLower(*new_idpin_hex);
  parameters["@idpuk_ascii"] = StringToLower(*idpuk_ascii);
  parameters["@newidpin_ascii"] = StringToLower(*new_idpin_ascii);

  // Initialize return values
  parameters["%returncode"] = "ff";
  parameters["%idpukstatus"] = "f3";

  // Step 1: Select the main application
  std::string response;
  sendAPDU((void **)&response, "00a4040010a0000000183003010000000000000000",
           13);

  // Step 2: Process the IDPUK
  parameters["%idpuk_4"] = parameters["@idpuk_hex"];

  // Check IDPUK length - ensure it's 4 bytes
  parameters["%length"] = GetLength("h");

  if (parameters["%length"] != "04") {
    // If not 4 bytes, calculate the difference and add padding
    parameters["%num"] = Sub(parameters["%length"], "04", "h");

    while (parameters["%num"] != "00") {
      // Add '00' padding bytes until we reach 4 bytes
      parameters["%idpuk_4"] = parameters["%idpuk_4"] + "00";
      parameters["%num"] = Sub("01", parameters["%num"], "h");
    }
  }

  // Step 3: Process the new ID PIN
  parameters["%newidpin_4"] = parameters["@newidpin_hex"];

  // Check new PIN length - ensure it's 4 bytes
  parameters["%length"] = GetLength("h");

  if (parameters["%length"] != "04") {
    // If not 4 bytes, calculate the difference and add padding
    parameters["%num"] = Sub(parameters["%length"], "04", "h");

    while (parameters["%num"] != "00") {
      // Add '00' padding bytes until we reach 4 bytes
      parameters["%newidpin_4"] = parameters["%newidpin_4"] + "00";
      parameters["%num"] = Sub("01", parameters["%num"], "h");
    }
  }

  // Step 4: Select the Master File and PIN file
  sendAPDU((void **)&response, "00a40000023f00", 42);
  sendAPDU((void **)&response, "00a40200020010", 44);

  // Step 5: Read ID flag to check if ID has been activated
  sendAPDU((void **)&response, "00b0000201", 47);
  parameters["%flag_id"] = *(std::string *)response;

  // Step 6: Process IDPUK for ID PIN application
  if (parameters["%flag_id"] != "0f") {
    // ID is activated - need to unblock it

    // First mark ID flag with "01"
    sendAPDU((void **)&response, "00d60002" + AddLen("01", "ISO7816"), 53);

    // Select the ID PIN directory
    sendAPDU((void **)&response, "00a40000023f00", 56);
    sendAPDU((void **)&response, "00a40100020200", 58);

    // Send APDU to unblock ID PIN and set new PIN
    std::string unblock_apdu =
        "8024010008" + parameters["%idpuk_4"] + parameters["%newidpin_4"];
    std::string expected_sw = "63,6983";
    sendAPDU((void **)&response, unblock_apdu, 61, &expected_sw);

    // Process response
    parameters["%sw"] = parameters["%lastresult"];

    if (parameters["%sw"] == "9000") {
      // Unblock successful
      parameters["%idpukstatuss"] = "11";

      // Update ID flag to 0F (deactivated)
      sendAPDU((void **)&response, "00a40000023f00", 80);
      sendAPDU((void **)&response, "00a40200020010", 82);
      sendAPDU((void **)&response, "00d60002" + AddLen("0f", "ISO7816"), 84);

      // Update flag_id parameter
      parameters["%flag_id"] = "0f";
    } else if (parameters["%sw"] == "6983") {
      // PUK blocked
      parameters["%idpukstatuss"] = "f2";
    } else {
      // Check SW1 byte
      parameters["%sw1"] =
          Truncate(log_buffer, 66, parameters["%sw"], "00", "01");

      if (parameters["%sw1"] == "63") {
        // PUK verification failed, tries remaining
        parameters["%idpukstatuss"] = "f1";
      } else {
        // Other error
        parameters["%idpukstatuss"] = "f2";
      }
    }
  } else {
    // ID is not activated
    parameters["%idpukstatuss"] = "11";
  }

  // Step 7: Process EVPUK for EV PIN application
  sendAPDU((void **)&response, "00a40000023f00", 91);
  sendAPDU((void **)&response, "00a40200020010", 92);

  // Read EV flag
  sendAPDU((void **)&response, "00b0000702", 94);
  parameters["%flag"] = *(std::string *)response;

  // Parse flags
  parameters["%flag_nmocpin"] =
      Truncate(log_buffer, 96, parameters["%flag"], "00", "01");
  parameters["%flag_evot"] =
      Truncate(log_buffer, 97, parameters["%flag"], "01", "01");

  if (parameters["%flag_evot"] == "0f") {
    // EV is deactivated
    parameters["%evpukstatus"] = "11";
  } else {
    // Set up EV flag depending on NMOC flag
    if (parameters["%flag_nmocpin"] != "02") {
      // Normal mode
      sendAPDU((void **)&response, "00d60007" + AddLen("0201", "ISO7816"), 111);
    } else {
      // NMOC mode
      sendAPDU((void **)&response, "00d60007" + AddLen("0201", "ISO7816"), 106);
    }

    // Select the EV PIN directory
    sendAPDU((void **)&response, "00a40000023f00", 115);
    sendAPDU((void **)&response, "00a40100020500", 117);

    // Send APDU to unblock EV PIN and set new PIN
    unblock_apdu =
        "8024010008" + parameters["%idpuk_4"] + parameters["%newidpin_4"];
    expected_sw = "63,6983";
    sendAPDU((void **)&response, unblock_apdu, 120, &expected_sw);

    // Process response
    parameters["%sw"] = parameters["%lastresult"];

    if (parameters["%sw"] == "9000") {
      // Unblock successful
      parameters["%evpukstatus"] = "11";

      // Update EV flag to deactivated
      sendAPDU((void **)&response, "00a40000023f00", 139);
      sendAPDU((void **)&response, "00a40200020010", 141);

      // Set different flags depending on NMOC flag
      if (parameters["%flag_nmocpin"] != "02") {
        // Normal mode
        sendAPDU((void **)&response, "00d60007" + AddLen("000f", "ISO7816"),
                 151);
        parameters["%flag_evot"] = "0f";
      } else {
        // NMOC mode
        sendAPDU((void **)&response, "00d60007" + AddLen("020f", "ISO7816"),
                 146);
      }
    } else if (parameters["%sw"] == "6983") {
      // PUK blocked
      parameters["%evpukstatus"] = "f2";
    } else {
      // Check SW1 byte
      parameters["%sw1"] =
          Truncate(log_buffer, 125, parameters["%sw"], "00", "01");

      if (parameters["%sw1"] == "63") {
        // PUK verification failed, tries remaining
        parameters["%evpukstatus"] = "f1";
      } else {
        // Other error
        parameters["%evpukstatus"] = "f2";
      }
    }
  }

  // Step 8: Process IAS application
  sendAPDU((void **)&response, "00a40000023f00", 158);
  sendAPDU((void **)&response, "00a40200020010", 159);

  // Read IAS flag
  sendAPDU((void **)&response, "00b0000301", 161);
  parameters["%flag_ias"] = *(std::string *)response;

  if (parameters["%flag_ias"] != "0f") {
    // IAS is activated - need to unblock it
    sendAPDU((void **)&response, "00d600030101", 167);

    // Select IAS application
    sendAPDU((void **)&response,
             "00a40400" + AddLen("a0000000180c000001634200", "ICAO"), 170);

    // Prepare IAS PIN data - needs to be 16 bytes
    parameters["%idpuk"] = parameters["@idpuk_ascii"];

    // Pad to 16 bytes
    while (GetLength("h") != "10") {
      parameters["%idpuk"] = parameters["%idpuk"] + "00";
    }

    // Prepare new PIN data - needs to be 16 bytes
    parameters["%newidpin"] = parameters["@newidpin_ascii"];

    // Pad to 16 bytes
    while (GetLength("h") != "10") {
      parameters["%newidpin"] = parameters["%newidpin"] + "00";
    }

    // Send APDU to unblock IAS PIN
    unblock_apdu =
        "002c008120" + parameters["%idpuk"] + parameters["%newidpin"];
    expected_sw = "63,6983,6984";
    sendAPDU((void **)&response, unblock_apdu, 193, &expected_sw);

    // Process response
    parameters["%sw"] = parameters["%lastresult"];

    if (parameters["%sw"] == "6983" || parameters["%sw"] == "6984") {
      // PUK blocked
      parameters["%iasstatus"] = "f2";
    } else {
      // Check SW1 byte
      parameters["%sw1"] =
          Truncate(log_buffer, 200, parameters["%sw"], "00", "01");

      if (parameters["%sw1"] == "90") {
        // Unblock successful
        parameters["%iasstatus"] = "11";

        // Select main application and mark IAS as deactivated
        sendAPDU((void **)&response,
                 "00a40400" +
                     AddLen("a0000000183003010000000000000000", "ISO7816"),
                 207);
        sendAPDU((void **)&response, "00a40000023f00", 209);
        sendAPDU((void **)&response, "00a40200020010", 211);
        sendAPDU((void **)&response, "00d60003010f", 213);
      } else if (parameters["%sw1"] == "63") {
        // PUK verification failed, tries remaining
        parameters["%iasstatus"] = "f1";
      } else {
        // Other error
        parameters["%iasstatus"] = "f2";
      }
    }
  } else {
    // IAS is not activated
    parameters["%iasstatus"] = "11";
  }

  // Step 9: Clean up flags and reset counter values
  sendAPDU((void **)&response, "00d600000100", 228);
  sendAPDU((void **)&response, "00d600010100", 229);
  sendAPDU((void **)&response, "00d600020100", 230);
  sendAPDU((void **)&response, "00d600030100", 231);
  sendAPDU((void **)&response, "00d600060100", 232);

  // Update flags depending on NMOC flag
  if (parameters["%flag_nmocpin"] != "02") {
    // Normal mode
    sendAPDU((void **)&response, "00d60007" + AddLen("0000", "ISO7816"), 241);
  } else {
    // NMOC mode
    sendAPDU((void **)&response, "00d60007" + AddLen("0200", "ISO7816"), 236);
  }

  // Step 10: Determine final status
  // First compare EV and ID PUK statuses
  parameters["%stat"] =
      Sub(parameters["%evpukstatus"], parameters["%idpukstatuss"], "h");
  parameters["%stat"] =
      Truncate(log_buffer, 247, parameters["%stat"], "00", "01");

  if (parameters["%stat"] == "ff") {
    // EV PUK status has precedence
    parameters["%mpstatus"] = parameters["%evpukstatus"];
  } else {
    // ID PUK status has precedence
    parameters["%mpstatus"] = parameters["%idpukstatuss"];
  }

  // Next compare MP and IAS statuses
  parameters["%st"] =
      Sub(parameters["%iasstatus"], parameters["%mpstatus"], "h");
  parameters["%st"] = Truncate(log_buffer, 257, parameters["%st"], "00", "01");

  if (parameters["%st"] == "ff") {
    // IAS status has precedence
    parameters["%idpukstatus"] = parameters["%iasstatus"];
  } else {
    // MP status has precedence
    parameters["%idpukstatus"] = parameters["%mpstatus"];
  }

  // Set successful return code
  parameters["%returncode"] = "00";

  // Copy values to output parameters
  *(std::string *)idpuk_status = parameters["%idpukstatus"];
  *(std::string *)return_code = parameters["%returncode"];

  // Mark function as finished
  function_name = "Finished";

  return 0;
}