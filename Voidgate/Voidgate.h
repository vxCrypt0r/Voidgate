#pragma once
#include <Windows.h>
#include <iostream>
#include <string.h>

constexpr DWORD SHELLCODE_PADDING		= 0x20;		// [SPONGE] padding for testing - removing later
constexpr DWORD MAX_X64_ASM_OPCODE_LEN	= 15;		// maximum lenght of x64 asm instructions is 15 bytes

extern DWORD64 payload_base;
extern DWORD64 payload_lower_bound;
extern DWORD64 payload_upper_bound;
extern DWORD64 last_decrypted_asm;

//This is the VEH routine responsible with encryption/decryption of each individual ASM instruction.
//Each instruction is executes sequentially by setting the TRAP flag in EFlags register.
//
//NOTE:
//The payload must respect the following requirements:
//	1.) Single-threaded payload (Work-In-Progress)
//	2.) Payload must not have values that must be read from the payload itself (such as having a string at the end of the payload that is referenced by a fixed offset.
//
//NOTE:
//The more instructions and loops the payload executes, the more the actual execution of the payload is slowed down, since for each ASM instruction executed
//the program will have to encrypt/decrypt them.
LONG VehDecryptHeapAsm(EXCEPTION_POINTERS* ExceptionInfo);

//This function calculates the starting position inside the key for each iteration inside the VEH.
//This starting position is used to determine the starting element inside the key that is used to encrypt/decrypt the ASM instruction.
DWORD GetXorKeyIndexForAsm(DWORD64 shellcode_base, DWORD64 current_asm_addr, std::string key);

//[SPONGE]
typedef NTSTATUS(WINAPI* VoidGate)(void);

//This function is responsible with setting the first HW Breakpoint on the payload entry point
BOOL SetHardwareBreakpoint(PVOID addr);

//This function is responsible with logging any WINAPI errors that may occur.
void LogWinapiError(std::string failedFunction);