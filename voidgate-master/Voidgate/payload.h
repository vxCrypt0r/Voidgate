#pragma once

#include<Windows.h>
#include<string>



extern BYTE payload[];		//Global variable holding the payload that needs to be executed.
extern DWORD payload_size;	//Global variable holdingt he payload size.
extern std::string key;		//Global variable holding the key for the XOR encrypted payload.