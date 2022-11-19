#pragma once
#include <Windows.h>
#include <vector>

namespace Utils
{
	void AttachConsole();
	void DetachConsole();
	bool ConsolePrint(const char* fmt, ...);
	uintptr_t PatternScan(LPCSTR module, LPCSTR pattern);
}