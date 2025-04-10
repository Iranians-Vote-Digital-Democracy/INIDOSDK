#include <memory>
#include <string>
#include <unordered_map>

#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <string>

namespace Clh {

/**
 * Converts an unsigned 64-bit integer to a hex string with even length
 * If the result has odd length, a leading '0' is added
 */
std::string UInt64ToHexStringEvenLen(uint64_t value) {
  std::stringstream stream;
  stream << std::hex << value;
  std::string result = stream.str();

  // Ensure even length
  if (result.length() % 2 != 0) {
    result = "0" + result;
  }

  return result;
}

/**
 * Converts an unsigned 64-bit integer to a string with the specified radix
 * Ensures the result has even length by prepending '0' if needed
 */
std::string UInt64ToStringEvenLen(uint64_t value, int radix) {
  // Convert number to string with requested radix
  std::stringstream stream;
  if (radix == 16) {
    stream << std::hex;
  } else if (radix == 10) {
    stream << std::dec;
  } else if (radix == 8) {
    stream << std::oct;
  }
  stream << value;
  std::string result = stream.str();

  // Ensure even length
  if (result.length() % 2 != 0) {
    result = "0" + result;
  }

  return result;
}

/**
 * Adds a length field to a hex string according to the specified format
 *
 * @param data The hex string to prepend with a length field
 * @param format The format for the length field (ISO7816, ICAO, etc.)
 * @return The string with the prepended length field
 */
std::string AddLen(const std::string &data, const std::string &format) {
  std::string result = data;

  // Ensure even length for the hex string
  if (result.length() % 2 != 0) {
    result = "0" + result;
  }

  // Calculate the byte length (half of hex string length)
  int byteLength = result.length() / 2;

  // Convert the length to hex
  std::string hexLength = UInt64ToHexStringEvenLen(byteLength);

  // Format the length field according to the specified format
  if (byteLength <= 127 || (byteLength <= 255 && format == "ISO7816")) {
    // Simple format: just take last 2 chars of the length in hex
    return hexLength.substr(hexLength.length() - 2) + result;
  } else if (byteLength <= 0xFFFF && format == "ISO7816Extended") {
    // ISO7816 extended format for lengths up to 65535 bytes
    return "00" + hexLength.substr(0, 4) + result;
  } else if (format == "ICAO") {
    if (byteLength <= 255) {
      // ICAO format for small lengths
      return "81" + hexLength.substr(hexLength.length() - 2) + result;
    } else if (byteLength <= 65535) {
      // ICAO format for larger lengths
      return "82" + hexLength.substr(0, 4) + result;
    }
  }

  // If we get here, the format is not supported or the length is too long
  throw std::runtime_error("MI : The mode of calculating length of hex string "
                           "is not correct. The mode is:'" +
                           format + "' and the len is '" +
                           std::to_string(byteLength) + "'.");
}

} // namespace Clh

// Structure to represent the Pardis_General_2 class
struct Pardis_General_2 {
  // Based on offsets observed in the code
  char buffer[104];                                        // 0-103
  char log_buffer[40];                                     // 104-143
  std::string function_name;                               // 144-?
  std::unordered_map<std::string, std::string> parameters; // At offset 184
  bool status_flag;                                        // At offset 1272

  // Helper methods for card operations
  void *sendAPDU(void **response, const std::string &apdu, int context_id,
                 const std::string *expected_sw = nullptr);

  // Helper methods for crypto and data manipulation
  static std::string Truncate(const char *context_buffer, int context_id,
                              const std::string &input, const std::string &from,
                              const std::string &to);
  static std::string Sub(const char *value1, const std::string &mode);
  static std::string Sub(const std::string &value1, const std::string &value2,
                         const std::string &mode);
  static std::string AddLen(const std::string &data, const std::string &prefix);
  static std::string TripleDesEncrypt(const char *context_buffer,
                                      int context_id, const std::string &data,
                                      const std::string &key,
                                      const std::string &mode);
  static std::string RetailCBC_MAC(const std::string &source);
  static std::string StringToLower(const std::string &input);

  // Main function we're implementing
  int64_t GetIDPINStatus(std::string *smd_key, void **idpin_status,
                         void **key_status, void **return_code);
};

/**
 * Gets the ID PIN status for the Pardis card
 *
 * @param smd_key The SMD key for secure messaging
 * @param idpin_status Output parameter for the ID PIN status
 * @param key_status Output parameter for the key status
 * @param return_code Output parameter for the return code
 * @return 0 on success
 */
int64_t Pardis_General_2::GetIDPINStatus(std::string *smd_key,
                                         void **idpin_status, void **key_status,
                                         void **return_code) {
  // Set status flag to active
  status_flag = true;

  // Set the function name for logging
  function_name = "GetIDPINStatus";

  // Store the SMD key in parameters
  std::string lowercase_key;
  lowercase_key = StringToLower(smd_key->c_str());
  parameters["@smdkey"] = lowercase_key;

  // Initialize return values
  parameters["%returncode"] = "ff";
  parameters["%idpinstatus"] = "f3";
  parameters["%keystatus"] = "f3";

  // Step 1: Select the Pardis application
  std::string aid = "a0000000d785013a0428";
  std::string select_apdu = "00a40400" + Clh::AddLen(aid, "ISO7816");
  std::string response;
  sendAPDU((void **)&response, select_apdu, 13);

  // Step 2: Select the master file
  sendAPDU((void **)&response, "00a40000023f00", 16);

  // Step 3: Get random challenge from card
  sendAPDU((void **)&response, "0084000008", 18);
  parameters["%c_rand"] = *(std::string *)response;

  // Step 4: Generate session keys
  // Create challenge sequences by appending counters to the random challenge
  parameters["%s1"] = parameters["%c_rand"] + "0000000000000001";
  parameters["%s2"] = parameters["%c_rand"] + "0000000000000002";

  // Generate encryption key using 3DES
  parameters["%sk_enc"] = TripleDesEncrypt(log_buffer, 21, parameters["%s1"],
                                           parameters["@smdkey"], "cbc");

  // Generate MAC key using 3DES
  parameters["%sk_mac"] = TripleDesEncrypt(log_buffer, 22, parameters["%s2"],
                                           parameters["@smdkey"], "cbc");

  // Step 5: Prepare secure messaging header and MAC
  parameters["%header"] = "0c200001";
  parameters["%ch"] = parameters["%header"] + "80000000";

  // Calculate MAC for the command
  parameters["%mac1"] =
      RetailCBC_MAC(parameters["%sk_mac"] + parameters["%ch"]);
  parameters["%mac2"] = "8e08" + parameters["%mac1"];

  // Step 6: Send VERIFY PIN command with secure messaging
  std::string verify_apdu =
      parameters["%header"] + Clh::AddLen(parameters["%mac2"], "ISO7816");
  sendAPDU((void **)&response, verify_apdu, 34, new std::string("all"));

  // Get response from card
  sendAPDU((void **)&response, "00c000000e", 37, new std::string("all"));

  // Process the response
  parameters["%sw"] = parameters["%lastresult"];
  parameters["%sw1"] = Truncate(log_buffer, 41, parameters["%sw"], "00", "01");

  // Check for error conditions (locked card or no tries remaining)
  if (parameters["%sw"] == "6984" || parameters["%sw"] == "63c0") {
    parameters["%keystatus"] = "11";
    parameters["%idpinstatus"] = "ffff";
    goto finish;
  }

  // Check for transport PIN
  if (parameters["%sw"] == "6988") {
    parameters["%keystatus"] = "f1";
    goto finish;
  }

  // Extract SW2 and calculate remaining tries
  parameters["%sw2"] = Truncate(log_buffer, 45, parameters["%sw"], "01", "01");
  parameters["%try"] = Sub(parameters["%sw2"], "c0", "h");

  // If we have remaining tries, process Matiran PIN status
  if (parameters["%try"] != "00") {
    parameters["%keystatus"] = "11";
    parameters["%idpin_matia1"] = parameters["%try"];

    // Step 7: Select Matiran application #1
    select_apdu = "00a40400" + Clh::AddLen("a0000000d785013a0429", "ISO7816");
    sendAPDU((void **)&response, select_apdu, 66);

    // Select master file
    sendAPDU((void **)&response, "00a40000023f00", 69);

    // Get random challenge
    sendAPDU((void **)&response, "0084000008", 71);
    parameters["%c_rand"] = *(std::string *)response;

    // Generate session keys again
    parameters["%s1"] = parameters["%c_rand"] + "0000000000000001";
    parameters["%s2"] = parameters["%c_rand"] + "0000000000000002";

    // Generate encryption and MAC keys
    parameters["%sk_enc"] = TripleDesEncrypt(log_buffer, 74, parameters["%s1"],
                                             parameters["@smdkey"], "cbc");
    parameters["%sk_mac"] = TripleDesEncrypt(log_buffer, 75, parameters["%s2"],
                                             parameters["@smdkey"], "cbc");

    // Prepare secure messaging header and MAC
    parameters["%header"] = "0c200001";
    parameters["%ch"] = parameters["%header"] + "80000000";

    // Calculate MAC
    parameters["%mac1"] =
        RetailCBC_MAC(parameters["%sk_mac"] + parameters["%ch"]);
    parameters["%mac2"] = "8e08" + parameters["%mac1"];

    // Send VERIFY PIN command with secure messaging
    verify_apdu =
        parameters["%header"] + Clh::AddLen(parameters["%mac2"], "ISO7816");
    sendAPDU((void **)&response, verify_apdu, 87,
             new std::string("63,6984,61"));

    // Get response
    sendAPDU((void **)&response, "00c000000e", 90,
             new std::string("63,6984,61"));

    // Process response
    parameters["%sw"] = parameters["%lastresult"];
    parameters["%sw1"] =
        Truncate(log_buffer, 95, parameters["%sw"], "00", "01");

    // Check for error conditions
    if (parameters["%sw"] == "6984" || parameters["%sw"] == "63c0") {
      parameters["%idpinstatus"] = "ffff";
    } else {
      // Extract SW2 and calculate remaining tries
      parameters["%sw2"] =
          Truncate(log_buffer, 98, parameters["%sw"], "01", "01");
      parameters["%try"] = Sub(parameters["%sw2"], "c0", "h");

      if (parameters["%try"] != "00") {
        parameters["%idpin_matia2"] = parameters["%try"];

        // Step 8: Select Pardis application
        select_apdu = "00a40400" +
                      Clh::AddLen("5041524449532c4d41544952414e20", "ISO7816");
        sendAPDU((void **)&response, select_apdu, 113);

        // Select master file and PIN file
        sendAPDU((void **)&response, "00a4000c023f00", 116);
        sendAPDU((void **)&response, "00a40000025000", 118);

        // Get random challenge
        sendAPDU((void **)&response, "0084000008", 120);
        parameters["%c_rand"] = *(std::string *)response;

        // Generate session keys
        parameters["%s1"] = parameters["%c_rand"] + "0000000000000001";
        parameters["%s2"] = parameters["%c_rand"] + "0000000000000002";

        // Generate encryption and MAC keys
        parameters["%sk_enc"] = TripleDesEncrypt(
            log_buffer, 123, parameters["%s1"], parameters["@smdkey"], "cbc");
        parameters["%sk_mac"] = TripleDesEncrypt(
            log_buffer, 124, parameters["%s2"], parameters["@smdkey"], "cbc");

        // Prepare secure messaging header and MAC for PIN verification
        parameters["%header"] = "0c200081";
        parameters["%ch"] = parameters["%header"] + "80000000";

        // Calculate MAC
        parameters["%mac1"] =
            RetailCBC_MAC(parameters["%sk_mac"] + parameters["%ch"]);
        parameters["%mac2"] = "8e08" + parameters["%mac1"];

        // Send VERIFY PIN command with secure messaging
        verify_apdu =
            parameters["%header"] + Clh::AddLen(parameters["%mac2"], "ISO7816");
        sendAPDU((void **)&response, verify_apdu, 136,
                 new std::string("63,6984,61"));

        // Get response
        sendAPDU((void **)&response, "00c000000e", 139,
                 new std::string("63,6984,61"));

        // Process response
        parameters["%sw"] = parameters["%lastresult"];
        parameters["%sw1"] =
            Truncate(log_buffer, 144, parameters["%sw"], "00", "01");

        // Check for error conditions
        if (parameters["%sw"] == "6984" || parameters["%sw"] == "63c0") {
          parameters["%idpinstatus"] = "ffff";
        } else {
          // Extract SW2 and calculate remaining tries
          parameters["%sw2"] =
              Truncate(log_buffer, 147, parameters["%sw"], "01", "01");
          parameters["%try"] = Sub(parameters["%sw2"], "c0", "h");

          if (parameters["%try"] != "00") {
            parameters["%idpin_pardis"] = parameters["%try"];

            // Determine which Matiran PIN to use (better of the two)
            parameters["%sub"] = Sub(parameters["%idpin_matia2"],
                                     parameters["%idpin_matia1"], "h");
            parameters["%sub"] =
                Truncate(log_buffer, 158, parameters["%sub"], "00", "01");

            if (parameters["%sub"] == "ff") {
              parameters["%idpin_matia"] = parameters["%idpin_matia1"];
            } else {
              parameters["%idpin_matia"] = parameters["%idpin_matia2"];
            }

            // Determine which PIN status to use (better of Matiran and Pardis)
            parameters["%sub"] = Sub(parameters["%idpin_pardis"],
                                     parameters["%idpin_matia"], "h");
            parameters["%sub"] =
                Truncate(log_buffer, 171, parameters["%sub"], "00", "01");

            if (parameters["%sub"] == "ff") {
              parameters["%idpinstatus"] = parameters["%idpin_matia"] + "00";
            } else {
              parameters["%idpinstatus"] = parameters["%idpin_pardis"] + "00";
            }
          } else {
            parameters["%idpinstatus"] = "ffff";
          }
        }
      } else {
        parameters["%idpinstatus"] = "ffff";
      }
    }
  }

finish:
  // Set the final return code
  parameters["%returncode"] = "00";

  // Copy values to output parameters
  *(std::string *)idpin_status = parameters["%idpinstatus"];
  *(std::string *)key_status = parameters["%keystatus"];
  *(std::string *)return_code = parameters["%returncode"];

  // Finish function
  function_name = "Finished";

  return 0;
}