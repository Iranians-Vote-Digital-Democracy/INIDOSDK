#include <algorithm>
#include <cstdint>
#include <memory>
#include <string>
#include <unordered_map>

// Forward declarations for helper classes/functions
namespace Clh {
std::string StringToLower(const std::string &input);
std::string Truncate(const char *context_buffer, int context_id,
                     const std::string &input, const std::string &from,
                     const std::string &to);
std::string Add(const std::string &value1, const std::string &value2,
                const std::string &mode);
std::string Sub(const std::string &value1, const std::string &mode);
std::string Sub(const std::string &value1, const std::string &value2,
                const std::string &mode);
std::string
ICAO_Plain2SMCommand(const char *context_buffer, int context_id,
                     const std::string &command, const std::string &sm_alg,
                     const std::string &key_enc, const std::string &key_mac,
                     const std::string &ssc, const char *increment = "01");
void ICAO_SM2PlainResponse(const char *context_buffer, int context_id,
                           const std::string &response,
                           const std::string &sm_alg,
                           const std::string &key_enc,
                           const std::string &key_mac, const std::string &ssc,
                           void **expected_sw, std::string *output_container);
std::string GetLength(const std::string &value, const std::string &mode);
std::string AddLen(const std::string &data, const std::string &format);
} // namespace Clh

// RuntimeError class for error handling
class RuntimeError {
public:
  void operator=(int64_t value) {}
};

// OMID2_MDAS_0 class definition
class OMID2_MDAS_0 {
private:
  char buffer[104];
  char log_buffer[40];
  std::string function_name;
  std::unordered_map<std::string, std::string> parameters;
  bool status_flag;
  RuntimeError error_state;

public:
  // Helper method for sending APDUs to the card
  static void **sendAPDU(int64_t context, void **response,
                         const std::string *command, int context_id,
                         const std::string *expected_status = nullptr);

  // Main verification function
  int64_t VerifyFinger_GAP(std::string *key_enc, std::string *key_mac,
                           std::string *ssc, std::string *finger_index,
                           std::string *finger_temp, std::string *rnd2_ifd,
                           void **output_ssc, void **output_gap_status,
                           void **output_pin_status, void **output_sign,
                           void **output_plain_data, void **output_bio_type,
                           void **output_return_code);
};

/*
This code represents a C++ implementation of the VerifyFinger_GAP method in the
OMID2_MDAS_0 class. The function is responsible for verifying fingerprint
biometric data using a secure messaging protocol. The implementation handles:

Converting input parameters and storing them in a parameters map
Selecting the signing application on the card
Getting a challenge from the card
Processing biometric verification data
Handling various response codes and error conditions
Returning the results via output parameters

I've maintained compatibility with the original decompiled code while making it
more readable and structured.
*/
int64_t OMID2_MDAS_0::VerifyFinger_GAP(
    std::string *key_enc, std::string *key_mac, std::string *ssc,
    std::string *finger_index, std::string *finger_temp, std::string *rnd2_ifd,
    void **output_ssc, void **output_gap_status, void **output_pin_status,
    void **output_sign, void **output_plain_data, void **output_bio_type,
    void **output_return_code) {
  // Set status flag to active
  status_flag = true;

  // Set the function name for logging
  function_name = "VerifyFinger_GAP";

  // Store input parameters in the parameters map
  parameters["@key_enc"] = Clh::StringToLower(key_enc->c_str());
  parameters["@key_mac"] = Clh::StringToLower(key_mac->c_str());
  parameters["@ssc"] = Clh::StringToLower(ssc->c_str());
  parameters["@finger_index"] = Clh::StringToLower(finger_index->c_str());
  parameters["@finger_temp"] = Clh::StringToLower(finger_temp->c_str());
  parameters["@rnd2_ifd"] = Clh::StringToLower(rnd2_ifd->c_str());

  // Initialize return values
  parameters["%returncode"] = "ff";
  parameters["%pinstatus"] = "";
  parameters["%gapstatus"] = "";
  parameters["%plaindata"] = "";
  parameters["%sign"] = "";
  parameters["%sm_alg"] = "aes";

  // Copy input parameter values to internal parameters
  parameters["%key_enc"] = parameters["@key_enc"];
  parameters["%key_mac"] = parameters["@key_mac"];
  parameters["%ssc"] = parameters["@ssc"];

  // Set the ID for the signing application
  parameters["%signidappaid_2"] = "398de5bab41ec676cabdb526e58572";

  // Copy rnd2_ifd parameter
  parameters["%rnd2_ifd"] = parameters["@rnd2_ifd"];

  // Step 1: Select the signing application
  std::string aid = parameters["%signidappaid_2"];
  std::string apdu_select = "00a40400" + Clh::AddLen(aid, "ICAO") + "00";

  // Create secure messaging command
  parameters["%cmdapdu"] = Clh::ICAO_Plain2SMCommand(
      log_buffer, 26, apdu_select, parameters["%sm_alg"],
      parameters["%key_enc"], parameters["%key_mac"], parameters["%ssc"], "01");

  // Send the secure select command
  void **response = sendAPDU((int64_t)this, nullptr, &parameters["%cmdapdu"],
                             28, new std::string("9000,6e00,6988"));

  // Store the response
  parameters["%resp"] = *(std::string *)response;

  // Get the status word from the response
  parameters["%sw"] = parameters["%lastresult"];

  // Check if the select was successful (SW = 9000)
  if (parameters["%sw"] != "9000") {
    // Select failed, handle error cases
    if (parameters["%sw"] == "6e00") {
      // Application not found
      parameters["%gapstatus"] = "f1";
    } else if (parameters["%sw"] == "6988") {
      // Selected file not available
      parameters["%gapstatus"] = "f2";
    }
  } else {
    // Select command succeeded
    parameters["%gapstatus"] = "11";

    // Increment SSC for next command
    parameters["%ssc"] = Clh::Add(parameters["%ssc"], "02", "h");

    // Step 2: Get Challenge command
    std::string get_challenge_apdu = "00ca002100";

    // Create secure messaging command for Get Challenge
    parameters["%cmdapdu"] = Clh::ICAO_Plain2SMCommand(
        log_buffer, 36, get_challenge_apdu, parameters["%sm_alg"],
        parameters["%key_enc"], parameters["%key_mac"], parameters["%ssc"],
        "01");

    // Send the secure Get Challenge command
    void **challenge_response =
        sendAPDU((int64_t)this, nullptr, &parameters["%cmdapdu"], 38,
                 new std::string("9000,6e00,6988"));

    // Store challenge response
    parameters["%outi"] = *(std::string *)challenge_response;
    parameters["%sw"] = parameters["%lastresult"];

    // Increment SSC for next command
    parameters["%ssc"] = Clh::Add(parameters["%ssc"], "01", "h");

    // Process the secure response to get plain data
    std::string resp_data = parameters["%outi"] + parameters["%sw"];

    Clh::ICAO_SM2PlainResponse(
        log_buffer + 104, 43, resp_data, parameters["%sm_alg"],
        parameters["%key_enc"], parameters["%key_mac"], parameters["%ssc"],
        (void **)&std::string("9000"), &parameters["%decresp"]);

    // Extract the random challenge from ICC
    parameters["%bit_group"] = parameters["%decresp.responsedata"];

    // Decrement SSC for verification
    parameters["%ssc"] = Clh::Sub(parameters["%ssc"], "01", "h");

    // Extract bit groups for verification
    parameters["%bit1"] =
        Clh::Truncate(log_buffer, 47, parameters["%bit_group"], "00", "34");

    parameters["%bit2"] =
        Clh::Truncate(log_buffer, 48, parameters["%bit_group"], "40", "34");

    // Extract ID information
    parameters["%id1"] =
        Clh::Truncate(log_buffer, 50, parameters["%bit1"], "05", "01");

    parameters["%id2"] =
        Clh::Truncate(log_buffer, 51, parameters["%bit2"], "05", "01");

    // Extract biometric index
    parameters["%bio_index1"] =
        Clh::Truncate(log_buffer, 54, parameters["%bit1"], "13", "01");

    parameters["%bio_index2"] =
        Clh::Truncate(log_buffer, 55, parameters["%bit2"], "13", "01");

    // Determine which biometric to use based on finger index
    if (parameters["@finger_index"] == parameters["%bio_index1"]) {
      parameters["%id"] = parameters["%id1"];
      // Convert ID (subtract 0x80 from it)
      parameters["%id"] = Clh::Sub(parameters["%id"], "80", "h");
    } else if (parameters["@finger_index"] == parameters["%bio_index2"]) {
      parameters["%id"] = parameters["%id2"];
      // Convert ID (subtract 0x80 from it)
      parameters["%id"] = Clh::Sub(parameters["%id"], "80", "h");
    }

    // Increment SSC for next command
    parameters["%ssc"] = Clh::Add(parameters["%ssc"], "02", "h");

    // Step 3: Get random number from the card
    parameters["%plain_data"] = "0084000008";

    // Create secure messaging command for Get Random
    parameters["%cmdapdu"] = Clh::ICAO_Plain2SMCommand(
        log_buffer, 84, parameters["%plain_data"], parameters["%sm_alg"],
        parameters["%key_enc"], parameters["%key_mac"], parameters["%ssc"],
        "9000");

    // Send the secure Get Random command
    void **random_response =
        sendAPDU((int64_t)this, nullptr, &parameters["%cmdapdu"], 86,
                 new std::string("9000,63,6a88,6100,6983,6984,61,6a80,6982"));

    // Store random response
    parameters["%resp1"] = *(std::string *)random_response;
    parameters["%sw"] = parameters["%lastresult"];

    // Extract SW1 and SW2 bytes
    parameters["%sw1"] =
        Clh::Truncate(log_buffer, 104, parameters["%sw"], "00", "01");

    parameters["%sw2"] =
        Clh::Truncate(log_buffer, 105, parameters["%sw"], "01", "01");

    // Process the response based on the status word
    if (parameters["%sw"] == "9000" || parameters["%sw1"] == "61") {
      // Success or more data available

      // If more data available, get the remaining data
      if (parameters["%sw1"] == "61") {
        response = sendAPDU((int64_t)this, nullptr, &std::string("0cc0000000"),
                            126, new std::string("6400,9000"));

        parameters["%resp2"] = *(std::string *)response;
        parameters["%sw"] = parameters["%lastresult"];
      }

      parameters["%pinstatus"] = "11"; // PIN OK

      // Combine responses if there was a second part
      if (parameters.find("%resp2") != parameters.end()) {
        parameters["%resp"] = parameters["%resp1"] + parameters["%resp2"];
      } else {
        parameters["%resp"] = parameters["%resp1"];
      }

      // Increment SSC for next operation
      parameters["%ssc"] = Clh::Add(parameters["%ssc"], "01", "h");

      // Process the secure response to get plain data
      resp_data = parameters["%resp"] + parameters["%sw"];

      Clh::ICAO_SM2PlainResponse(
          log_buffer + 104, 136, resp_data, parameters["%sm_alg"],
          parameters["%key_enc"], parameters["%key_mac"], parameters["%ssc"],
          (void **)&std::string("9000"), &parameters["%decresp"]);

      // Extract the total signature data
      parameters["%totalsign"] = parameters["%decresp.responsedata"];

      // Get the length of the total signature
      parameters["%totalsign_l"] =
          Clh::GetLength(parameters["%totalsign"], "d");

      // Extract biometric type
      parameters["%biotype"] =
          Clh::Truncate(log_buffer, 142, parameters["%totalsign"], "00", "01");

      // Extract the signature
      parameters["%sign"] = Clh::Truncate(
          log_buffer, 144, parameters["%totalsign"], "01", "0256");

      // Calculate remaining length
      parameters["%rest_l"] = Clh::Sub(parameters["%totalsign_l"], "0257", "d");

      // Extract the encrypted template
      parameters["%encryptedtemp"] =
          Clh::Truncate(log_buffer, 147, parameters["%totalsign"], "0257",
                        parameters["%rest_l"]);

      // Construct the plain data result
      parameters["%plaindata"] = parameters["%rnd2_ifd"] +
                                 parameters["%encryptedtemp"] + "9000" +
                                 parameters["%rnd_icc"];

      // Decrement SSC for verification
      parameters["%ssc"] = Clh::Sub(parameters["%ssc"], "01", "h");
    } else if (parameters["%sw"] == "6984" || parameters["%sw"] == "6983" ||
               parameters["%sw"] == "63c0") {
      // PIN verification failed
      parameters["%pinstatus"] = "f2";
    } else if (parameters["%sw"] == "63c1") {
      // PIN verification failed, tries remaining
      parameters["%pinstatus"] = "f5";
    } else if (parameters["%sw1"] == "63") {
      // PIN tries remaining
      parameters["%pinstatus"] = "f1";
    } else if (parameters["%sw"] == "6a88") {
      // Referenced data not found
      parameters["%pinstatus"] = "f4";
    } else if (parameters["%sw"] == "6a80") {
      // Incorrect parameters in the command data field
      parameters["%pinstatus"] = "f6";
    } else if (parameters["%sw"] == "6982") {
      // Security status not satisfied
      parameters["%pinstatus"] = "f7";
    }

    // Increment SSC for next operation
    parameters["%ssc"] = Clh::Add(parameters["%ssc"], "02", "h");
  }

  // Set the final return code
  parameters["%returncode"] = "00";

  // Copy values to output parameters
  *(std::string *)output_ssc = parameters["%ssc"];
  *(std::string *)output_gap_status = parameters["%gapstatus"];
  *(std::string *)output_pin_status = parameters["%pinstatus"];
  *(std::string *)output_sign = parameters["%sign"];
  *(std::string *)output_plain_data = parameters["%plaindata"];
  *(std::string *)output_bio_type = parameters["%biotype"];
  *(std::string *)output_return_code = parameters["%returncode"];

  // Complete the function
  function_name = "";

  return 0;
}