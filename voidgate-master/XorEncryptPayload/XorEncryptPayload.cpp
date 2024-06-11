#include <Windows.h>
#include <iostream>

void PrintWinapiError(std::string failedFuncName)
{
    std::cout << "[X] ERROR - WINAPI " + failedFuncName + " failed with error code: 0x" << std::hex << GetLastError() << std::endl;
}
void PrintProgramFail(std::string failMessage)
{
    std::cout << "[X] FAIL - " + failMessage << std::endl;
}

BOOL CheckProgramArgs(INT argc, CHAR** argv)
{
    if (argc != 2)
    {
        std::cout << "[X] ERROR - Provide path to payload to XOR encrypt... Example:" << std::endl;
        std::cout << argv[0] << +" C:\\Windows\\temp\\payload.bin" << std::endl;
        return FALSE;
    }
    return TRUE;
}
void XorEncryptPayload(PBYTE dataToEncrypt, DWORD64 dataSize, std::string xorKey)
{
    std::cout << "{ ";
    INT keyReadIndex = 0;
    for (INT i = 0; i < dataSize; i++)
    {
        if (keyReadIndex == xorKey.size())
        {
            keyReadIndex = 0;
        }

        dataToEncrypt[i] ^= xorKey[keyReadIndex];
        std::cout << " 0x" << std::hex << (DWORD)dataToEncrypt[i];
        if (i < dataSize - 1)
        {
            std::cout << ",";
        }
        keyReadIndex++;
    }
    std::cout << " }; " << std::endl;
}

INT main(INT argc, CHAR** argv)
{

    if (!CheckProgramArgs(argc, argv))
    {
        return EXIT_FAILURE;
    }

    HANDLE fileHandle = INVALID_HANDLE_VALUE;
    PVOID fileData = nullptr;
    LARGE_INTEGER fileSize = { 0 };
    DWORD bytesRead = 0;
    DWORD status = 0;

    std::string xorKey = "0dAd2!@BS1dtdCgPMWoA";

    fileHandle = CreateFileA(argv[1], GENERIC_ALL, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (fileHandle == INVALID_HANDLE_VALUE)
    {
        PrintWinapiError("CreateFileA");
        PrintProgramFail("Failed to get a handle to the file... Exiting...");
        status = EXIT_FAILURE;
        goto exit;
    }


    if (!GetFileSizeEx(fileHandle, &fileSize))
    {
        PrintWinapiError("GetFileSizeEx");
        PrintProgramFail("Failed to get the size of the file... Exiting...");
        status = EXIT_FAILURE;
        goto exit_close_file_handle;
    }

    fileData = VirtualAlloc(NULL, fileSize.QuadPart, MEM_COMMIT, PAGE_READWRITE);
    if (!fileData)
    {
        PrintWinapiError("VirtualAlloc");
        PrintProgramFail("Failed to allocate memory to read the contents of the file... Exiting...");
        status = EXIT_FAILURE;
        goto exit_close_file_handle;
    }

    if (!ReadFile(fileHandle, fileData, fileSize.QuadPart, &bytesRead, NULL))
    {
        PrintWinapiError("ReadFile");
        PrintProgramFail("Failed to read the file data... Exiting...");
        status = EXIT_FAILURE;
        goto exit_free_memory;
    }

    XorEncryptPayload((PBYTE)fileData, fileSize.QuadPart, xorKey);
    status = EXIT_SUCCESS;


exit_free_memory:
    VirtualFree(fileData, NULL, MEM_RELEASE);
exit_close_file_handle:
    CloseHandle(fileHandle);
exit:
    return status;
}
