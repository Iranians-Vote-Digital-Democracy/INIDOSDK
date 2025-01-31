#include <windows.h>
#include <winscard.h>
#include <iostream>
#include <vector>
#include <string>

#pragma comment(lib, "winscard.lib")

//Constants for PC/SC
#define GET_UID_COMMAND {0xFF, 0xCA, 0x00, 0x00, 0x00} // APDU to retrieve UID
#define SW1_SUCCESS 0x90                               // SW1 success byte
#define SW2_SUCCESS 0x00                               // SW2 success byte

//Function to initialize the PC/SC context
SCARDCONTEXT initializeContext()
{
    SCARDCONTEXT context;
    LONG status = SCardEstablishContext(SCARD_SCOPE_SYSTEM, nullptr, nullptr, &context);
    if (status != SCARD_S_SUCCESS)
    {
        std::cerr << "Failed to establish context. Error: " << std::hex << status << std::endl;
        exit(EXIT_FAILURE);
    }
    std::cout << "Context established successfully." << std::endl;
    return context;
}

//Function to list all available readers
std::vector<std::string> listReaders(SCARDCONTEXT context)
{
    LPSTR readersMultiString = nullptr;
    DWORD readersLen = SCARD_AUTOALLOCATE;
    LONG status = SCardListReadersA(context, nullptr, reinterpret_cast<LPSTR>(&readersMultiString), &readersLen);

    if (status != SCARD_S_SUCCESS)
    {
        std::cerr << "Failed to list readers. Error: " << std::hex << status << std::endl;
        exit(EXIT_FAILURE);
    }

    std::vector<std::string> readers;
    LPSTR reader = readersMultiString;
    while (*reader)
    {
        readers.push_back(reader);
        reader += strlen(reader) + 1;
    }

    SCardFreeMemory(context, readersMultiString);
    return readers;
}

//Function to connect to a specific reader
SCARDHANDLE connectToReader(SCARDCONTEXT context, const std::string& readerName)
{
    SCARDHANDLE cardHandle;
    DWORD activeProtocol;
    LONG status = SCardConnectA(context, readerName.c_str(), SCARD_SHARE_SHARED, SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1, &cardHandle, &activeProtocol);

    if (status != SCARD_S_SUCCESS)
    {
        std::cerr << "Failed to connect to reader: " << readerName << ". Error: " << std::hex << status << std::endl;
        exit(EXIT_FAILURE);
    }

    std::cout << "Connected to reader: " << readerName << std::endl;
    return cardHandle;
}

//Function to send the GET UID command and retrieve the response
std::vector<uint8_t> getCardUID(SCARDHANDLE cardHandle)
{
    const BYTE command[] = GET_UID_COMMAND;
    BYTE response[256];
    DWORD responseLen = sizeof(response);

    LONG status = SCardTransmit(cardHandle, SCARD_PCI_T1, command, sizeof(command), nullptr, response, &responseLen);

    if (status != SCARD_S_SUCCESS)
    {
        std::cerr << "Failed to transmit command. Error: " << std::hex << status << std::endl;
        exit(EXIT_FAILURE);
    }

    // Validate response length and success status
    if (responseLen < 2 || response[responseLen - 2] != SW1_SUCCESS || response[responseLen - 1] != SW2_SUCCESS)
    {
        std::cerr << "Invalid response from card. SW1: " << std::hex << response[responseLen - 2]
            << " SW2: " << std::hex << response[responseLen - 1] << std::endl;
        exit(EXIT_FAILURE);
    }

    // Extract UID (exclude SW1 and SW2)
    return std::vector<uint8_t>(response, response + responseLen - 2);
}

int main()
{
    SCARDCONTEXT context = initializeContext();
    auto readers = listReaders(context);

    if (readers.empty())
    {
        std::cerr << "No readers available." << std::endl;
        SCardReleaseContext(context);
        return EXIT_FAILURE;
    }

    std::cout << "Available readers:" << std::endl;
    for (const auto& reader : readers)
    {
        std::cout << "  " << reader << std::endl;
    }

   // Connect to the first available reader
    SCARDHANDLE cardHandle = connectToReader(context, readers[0]);

   // Retrieve and print the card UID
    auto uid = getCardUID(cardHandle);

    std::cout << "Card UID: ";
    for (auto byte : uid)
    {
        std::cout << std::hex << (int)byte << " ";
    }
    std::cout << std::dec << std::endl;

   // Disconnect and release resources
    SCardDisconnect(cardHandle, SCARD_LEAVE_CARD);
    SCardReleaseContext(context);

    return EXIT_SUCCESS;
}
