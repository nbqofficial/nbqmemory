#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <iostream>

#define in_range(x, a, b) (x >= a && x <= b)
#define get_bits(x) (in_range(x, '0', '9') ? (x - '0') : ((x & (~0x20)) - 'A' + 0xa))
#define get_byte(x) (get_bits(x[0]) << 4 | get_bits(x[1]))

typedef struct _module
{
	DWORD base;
	DWORD size;
}module, * pmodule;

class nbqmemory
{
	private:

		HANDLE process_handle = NULL;

	public:

		nbqmemory();

		nbqmemory(const char* process_name, DWORD access_rights);

		~nbqmemory();

		bool attach(const char* process_name, DWORD access_rights);

		bool detach();

		module get_module(const char* module_name);

		bool compare_memory(const byte* data, const char* pattern);

		DWORD pattern_scan(module mod, const char* pattern, int offset, int extra, bool relative, bool subtract);

		template <typename t>
		t read_memory(DWORD address);

		template <typename t>
		void write_memory(DWORD address, t value);
	
};

template<typename t>
inline t nbqmemory::read_memory(DWORD address)
{
	t buffer;
	ReadProcessMemory(this->process_handle, (LPCVOID)address, &buffer, sizeof(t), NULL);
	return buffer;
}

template<typename t>
void nbqmemory::write_memory(DWORD address, t buffer)
{
	WriteProcessMemory(this->process_handle, (LPVOID)address, &buffer, sizeof(t), NULL);
}
