# Read PINs Flags

## Select Main Application

We use the command **00a4040010a0000000183003010000000000000000** to select the main application. The command is structured as follows:

- **CLA (00):** Command class.
- **INS (A4):** Select instruction.
- **P1 (04):** Indicates selection by name.
- **P2 (00):** No special parameters.
- **Lc (10):** Specifies 16 bytes of data.
- **Data:** The AID `a0000000183003010000000000000000` identifies the application.

**Expected Response:** 
- **Success:** `9000` (SW_NO_ERROR)
- **Error:** `6A82` (File not found)

## Select Master File

The command **00a40000023f00** is used to select the Master File. Its structure is:

- **CLA (00):** Command class.
- **INS (A4):** Select instruction.
- **P1 (00) & P2 (00):** Default parameters.
- **Lc (02):** Indicates 2 bytes of data.
- **Data:** The file identifier `3f00` representing the Master File.

**Expected Response:**
- **Success:** `9000` (SW_NO_ERROR)
- **Error:** `6A82` (File not found)

## Select PIN Status File

We send **00a40200020010** to select the PIN status file. In this command:

- **CLA (00):** Command class.
- **INS (A4):** Select instruction.
- **P1 (02):** Indicates an alternative selection mode.
- **P2 (00):** No additional parameters.
- **Lc (02):** Indicates 2 bytes of data.
- **Data:** The file identifier `0010` which points to the PIN status file.

**Expected Response:**
- **Success:** `9000` (SW_NO_ERROR)
- **Error:** `6A82` (File not found)

## Read Sign PIN Flag

The command **00b0000402** reads the sign PIN flag. Its breakdown is:

- **CLA (00):** Command class.
- **INS (B0):** Read Binary instruction.
- **P1 (00):** Indicates start offset high byte.
- **P2 (04):** Offset within the file.
- **Le (02):** Requests 2 bytes of data.

**Expected Response:**
- **Success:** `XXXX9000` where `XXXX` is the PIN flag data
  - `1100` indicates PIN is active
  - `F100` indicates PIN is not active
  - `F200` indicates PIN is blocked
- **Error:** `6A82` (File not found)

The returned value is stored for further evaluation of the sign PIN status.

## Read ID PIN Flag

To read the ID PIN flag, we issue **00b0000502**. The structure is:

- **CLA (00):** Command class.
- **INS (B0):** Read Binary instruction.
- **P1 (00):** Starting offset high byte.
- **P2 (05):** Offset within the file.
- **Le (02):** Requests 2 bytes.

**Expected Response:**
- **Success:** `XXXX9000` where `XXXX` is the PIN flag data
  - `1100` indicates PIN is active
  - `F100` indicates PIN is not active
  - `F200` indicates PIN is blocked
- **Error:** `6A82` (File not found)

This response is later interpreted to determine the ID PIN status.

## Read NMOC PIN Flag

The final APDU command is **00b0000702** which reads the NMOC PIN flag. Its components are:

- **CLA (00):** Command class.
- **INS (B0):** Read Binary instruction.
- **P1 (00):** Starting offset high byte.
- **P2 (07):** Offset within the file.
- **Le (02):** Requests 2 bytes.

**Expected Response:**
- **Success:** `XXXX9000` where `XXXX` is the PIN flag data
  - `1100` indicates PIN is active
  - `F100` indicates PIN is not active
  - `F200` indicates PIN is blocked
- **Error:** `6A82` (File not found) [[1]](#sources)

The retrieved data is then processed using a truncation helper to extract the relevant part before deciding if the NMOC PIN is active.

## PIN Verification

To verify PINs, the following APDU commands are used:

### Verify ID PIN

The command is **0020000008** + PIN_DATA, where PIN_DATA is 8 bytes (16 hex chars) of PIN data, padded if needed:

- **CLA (00):** Command class.
- **INS (20):** VERIFY instruction.
- **P1 (00) & P2 (00):** Default parameters for PIN verification.
- **Lc (08):** Specifies 8 bytes of PIN data.
- **Data:** The PIN value, padded to 8 bytes.

**Expected Responses:**
- **Success:** `9000` (PIN Verified)
- **Failed with X attempts remaining:** `63CX` (where X is remaining attempts, e.g., `63C3`, `63C2`, `63C1`)  
- **PIN Blocked:** `6983` (Authentication method blocked)

### Verify IAS PIN

For the IAS application, the command is **0020008110** + PIN_DATA, where PIN_DATA is 16 bytes (32 hex chars) of PIN data:

- **CLA (00):** Command class.
- **INS (20):** VERIFY instruction.
- **P1 (00) & P2 (81):** Parameters for IAS PIN verification.
- **Lc (10):** Specifies 16 bytes of PIN data.
- **Data:** The PIN value, padded to 16 bytes.

**Expected Responses:**
- **Success:** `9000` (PIN Verified)
- **Failed with X attempts remaining:** `63CX` (where X is remaining attempts)
- **PIN Blocked:** `6983` (Authentication method blocked)
- **Reference data not found:** `6984`


## Sources:
1. p.12, ISO_7816-4_2005

## Questions:
1. Is there a default PIN?!
- ["last four digits of national number"](https://www.entekhab.ir/fa/news/406270/%D8%B1%D9%85%D8%B2-%DA%A9%D8%A7%D8%B1%D8%AA-%D9%87%D9%88%D8%B4%D9%85%D9%86%D8%AF-%D9%85%D9%84%DB%8C-%DB%B4-%D8%B1%D9%82%D9%85-%D8%A2%D8%AE%D8%B1-%DA%A9%D8%AF-%D9%85%D9%84%DB%8C-%D8%A7%D8%B3%D8%AA)
- ["1234"](https://mahzarchi.ir/education/6527/#:~:text=%D9%86%DA%A9%D8%AA%D9%87%20%D9%82%D8%A7%D8%A8%D9%84%20%D8%AA%D9%88%D8%AC%D9%87%20%D8%A7%DB%8C%D9%86%DA%A9%D9%87%20%D8%B1%D9%85%D8%B2%20%D8%A7%DA%A9%D8%AB%D8%B1%20%DA%A9%D8%A7%D8%B1%D8%AA%E2%80%8C%D9%87%D8%A7%DB%8C%20%D9%87%D9%88%D8%B4%D9%85%D9%86%D8%AF%20%D9%85%D9%84%DB%8C%20%D9%85%D8%B9%D9%85%D9%88%D9%84%D8%A7%D9%8B%201234%20%D9%85%DB%8C%E2%80%8C%D8%A8%D8%A7%D8%B4%D8%AF.%20%28%DA%86%D8%B1%D8%A7%DA%A9%D9%87%20%D9%85%D9%85%DA%A9%D9%86%20%D8%A7%D8%B3%D8%AA%20%D8%A7%DA%A9%D8%AB%D8%B1%20%D8%A7%D9%81%D8%B1%D8%A7%D8%AF%20%D9%88%20%D8%B4%D8%A7%DB%8C%D8%AF%20%D8%AE%D9%88%D8%AF%20%D8%B4%D9%85%D8%A7%20%D9%87%D9%85%20%D8%B1%D9%85%D8%B2%20%DA%A9%D8%A7%D8%B1%D8%AA%20%D9%87%D9%88%D8%B4%D9%85%D9%86%D8%AF%20%D9%85%D9%84%DB%8C%20%D8%AE%D9%88%D8%AF%20%D8%B1%D8%A7%20%D9%86%D8%AF%D8%A7%D9%86%DB%8C%D8%AF%29)