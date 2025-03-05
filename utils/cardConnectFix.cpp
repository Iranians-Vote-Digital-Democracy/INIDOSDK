#include <windows.h>
#include <winscard.h>
#include <iostream>
#include <string>
#include <vector>
#include <stdexcept>
#pragma comment(lib, "winscard.lib")

static LONG dk_FindCardReader(std::vector<std::string>& outReaders, SCARDCONTEXT context)
{
    if (!context)
    {
        return SCARD_E_INVALID_PARAMETER; // or handle "no context" as needed
    }

    DWORD requiredSize = 0;
    LONG result = SCardListReadersA(
        context,
        nullptr,       // mszGroups
        nullptr,       // mszReaders
        &requiredSize
    );
    if (result != SCARD_S_SUCCESS)
    {
        return result; // pass the same error code up
    }

    // Allocate a buffer to hold the multi-string result
    std::vector<char> readersBuffer(requiredSize + 1, '\0');

    // 2nd call to actually get the reader names
    result = SCardListReadersA(
        context,
        nullptr,
        readersBuffer.data(),
        &requiredSize
    );
    if (result != SCARD_S_SUCCESS)
    {
        return result;
    }

    // Convert the double-null-terminated list to a std::vector<std::string>
    // The format is "Reader1\0Reader2\0...ReaderN\0\0".
    const char* p = readersBuffer.data();
    while (*p != '\0')
    {
        std::string readerName(p);
        outReaders.push_back(readerName);
        p += (readerName.size() + 1);
    }

    // Now release the context after listing (per pseudocode)
    result = SCardReleaseContext(context);
    if (result != SCARD_S_SUCCESS)
    {
        return result;
    }

    return SCARD_S_SUCCESS; // success
}


static int64_t dk_SCardConnect_0(SCARDCONTEXT phContext, std::string& reader, SCARDHANDLE* phCard) {
    DWORD pdwActiveProtocol;
    LONG connect = SCardConnectA(phContext, reader.c_str(),
        SCARD_SHARE_EXCLUSIVE,
        SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
        phCard, &pdwActiveProtocol);
    printf("SCardConnectA result = %#.8x\n", connect);
    if (connect == SCARD_W_REMOVED_CARD)
        return 802005LL;
    if (connect)
        return 802002LL;
    return 0LL;
}

int ConnnectToCardAndDoNothing()
{
    printf("[+] ConnnectToCardAndDoNothing START\n");
    SCARDCONTEXT phContext1;
    LONG result = SCardEstablishContext(0, 0LL, 0LL, &phContext1);
    if (result != SCARD_S_SUCCESS) {
        printf("[1] SCardEstablishContext failed | result = %#.8x\n", result);
        return 0;
    }
    SCARDCONTEXT phContext2;
    result = SCardEstablishContext(0, 0LL, 0LL, &phContext2);
    std::vector<std::string> outReaders;
    if (result || dk_FindCardReader(outReaders, phContext2)) {
        printf("[2] SCardEstablishContext failed | result = %#.8x\n", result);
        return 0;
    }

    printf("outReaders[0] = %s\n", outReaders[0].c_str());
    SCARDHANDLE phCard;
    int64_t connect = dk_SCardConnect_0(phContext1, outReaders[0], &phCard);
    printf("connect = %I64d\n", connect);
    if (connect == 0) {
        printf("[+] successfully connected\n");
    }
    SCardDisconnect(phCard, SCARD_LEAVE_CARD);

    if (SCardReleaseContext(phContext1) != SCARD_S_SUCCESS)
    {
        printf("[-] Failed to release context for phContext1\n");
    }
    if (SCardReleaseContext(phContext2) != SCARD_S_SUCCESS)
    {
        printf("[-] Failed to release context for phContext2\n");
    }

    printf("[+] ConnnectToCardAndDoNothing END\n");
    // Done
    return 0;
}
