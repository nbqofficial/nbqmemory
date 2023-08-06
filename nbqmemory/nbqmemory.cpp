#include "nbqmemory.h"

#include <cstdio>
#include <TlHelp32.h>

template <typename... Args>
void debug_log(Args... args) {
#ifdef _DEBUG
	(void)printf(args...);
#endif // _DEBUG
}

nbqmemory::nbqmemory(const char* process_name, DWORD access_rights) {
	if (!attach(process_name, access_rights)) {
		debug_log("[-] Failed to attach to the process %s with access rights %lu\n", process_name, access_rights);
	}
}

void nbqmemory::detach() {
	if (this->process_handle && !CloseHandle(this->process_handle)) {
		debug_log("[-] Failed to detach\n");
	}
}

nbqmemory::~nbqmemory() {
	detach();
}

DWORD search_for_process_id(const char* process_name) {
	HANDLE process_snapshot_handle = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, NULL);
	if (!process_snapshot_handle) {
		debug_log("[-] Failed to take a snapshot of processes, last error %lu\n", GetLastError());
		return 0;
	}

	PROCESSENTRY32 process_entry{ sizeof(PROCESSENTRY32) };

	if (Process32First(process_snapshot_handle, &process_entry)) {
		do {
			if (strcmp(process_entry.szExeFile, process_name) == 0) {
				return process_entry.th32ProcessID;
			}
		} while (Process32Next(process_snapshot_handle, &process_entry));
	}
	else {
		debug_log("[-] Failed to copy the first process entry to the buffer, last error %lu\n", GetLastError());
	}

	(void)CloseHandle(process_snapshot_handle);

	return 0;
}

bool nbqmemory::attach(const char* process_name, DWORD access_rights) {
	DWORD pid = search_for_process_id(process_name);
	this->process_handle = OpenProcess(access_rights, false, pid);

	// This will print even when we fail to open a handle, not sure if you really want this...
	debug_log("[=] process_handle(%s): 0x%08X\n", process_name, reinterpret_cast<DWORD>(this->process_handle));

	return static_cast<bool>(this->process_handle);
}

module nbqmemory::get_module(const char* module_name) {
	module mod = { 0 };
	HANDLE ss = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetProcessId(this->process_handle));
	if (ss) {
		MODULEENTRY32 me;
		me.dwSize = sizeof(MODULEENTRY32);
		if (Module32First(ss, &me)) {
			do
			{
				if (!strcmp(me.szModule, module_name)) {
					mod.base = (DWORD)me.modBaseAddr;
					mod.size = (DWORD)me.modBaseSize;
					break;
				}
			} while (Module32Next(ss, &me));
		}
		CloseHandle(ss);
	}
	return mod;
}

bool nbqmemory::compare_memory(const byte* data, const char* pattern) {
	for (; *pattern; *pattern != ' ' ? ++data : data, ++pattern) {

		if (*pattern == ' ' || *pattern == '?')
			continue;
		if (*data != get_byte(pattern))
			return false;

		++pattern;
	}
	return true;
}

DWORD nbqmemory::pattern_scan(module mod, const char* pattern, int offset, int extra, bool relative, bool subtract) {
	DWORD address = 0;

	byte* data = new byte[mod.size];
	ReadProcessMemory(this->process_handle, (LPCVOID)mod.base, data, mod.size, NULL);

	for (DWORD i = 0x1000; i < mod.size; i++) {
		if (compare_memory((const byte*)(data + i), pattern)) {
			address = mod.base + i + offset;

			if (relative)
				ReadProcessMemory(this->process_handle, LPCVOID(address), &address, sizeof(DWORD), NULL);
			if (subtract)
				address -= mod.base;

			address += extra;
			break;
		}
	}

	delete[] data;
	return address;
}
