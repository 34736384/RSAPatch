#include <Windows.h>
#include <winternl.h>
#include <intrin.h>
#include <fstream>
#include <filesystem>
#include <string>
#include "detours.h"
#include "Utils.h"
#include "exports.h"

#pragma comment(lib, "detours.lib")
#pragma comment(lib, "ntdll.lib")

typedef enum _SECTION_INFORMATION_CLASS {
	SectionBasicInformation,
	SectionImageInformation
} SECTION_INFORMATION_CLASS, * PSECTION_INFORMATION_CLASS;
EXTERN_C NTSTATUS __stdcall NtQuerySection(HANDLE SectionHandle, SECTION_INFORMATION_CLASS InformationClass, PVOID InformationBuffer, ULONG InformationBufferSize, PULONG ResultLength);
EXTERN_C NTSTATUS __stdcall NtProtectVirtualMemory(HANDLE ProcessHandle, PVOID* BaseAddress, PULONG  NumberOfBytesToProtect, ULONG NewAccessProtection, PULONG OldAccessProtection);

template <typename T>
class Array
{
	class Bounds
	{
	public:
		uintptr_t length;
		int32_t lower_bound;
	};
public:
	void* klass;
	void* monitor;
	Bounds* bounds;
	size_t max_length;
	T vector[32];

	size_t length() {
		if (bounds)
			return bounds->length;
		return max_length;
	}

};

PVOID oGetPublicKey = nullptr;
PVOID oGetPrivateKey = nullptr;


PVOID Detour(PVOID func, PVOID jmp, bool attach)
{
	if (!func)
		return nullptr;

	PVOID call = func;
	DetourTransactionBegin();
	DetourUpdateThread((HANDLE)-2);
	if (attach)
		DetourAttach(&call, jmp);
	else
		DetourDetach(&call, jmp);
	DetourTransactionCommit();

	return call;
}

std::string ReadFile(std::string path)
{
	std::ifstream ifs(path);
	if (!ifs.good())
	{
		Utils::ConsolePrint("Failed to Open: %s\n", path.c_str());
		return {};
	}

	std::string result;
	ifs >> result;
	return result;
}

Array<BYTE>* __fastcall hkGetRSAKey()
{
	static PVOID privateKeyRet = nullptr;
	static PVOID publicKeyRet = nullptr;

	auto ret = _ReturnAddress();

	// it will always called for private key first then public key
	if (!privateKeyRet)
		privateKeyRet = ret;
	else if (!publicKeyRet)
		publicKeyRet = ret;

	bool isPrivate = ret == privateKeyRet;
	auto data = decltype(&hkGetRSAKey)(isPrivate ? oGetPrivateKey : oGetPublicKey)();
	std::string customKey{};

	if (isPrivate)
	{
		Utils::ConsolePrint("private\n");
		customKey = ReadFile("PrivateKey.txt");
	}
	else
	{
		Utils::ConsolePrint("public\n");
		customKey = ReadFile("PublicKey.txt");
	}

	if (!customKey.empty())
	{
		if (customKey.size() <= data->length())
		{
			ZeroMemory(data->vector, data->length());
			memcpy_s(data->vector, data->length(), customKey.data(), customKey.size());
		}
		else
		{
			Utils::ConsolePrint("custom key longer than original\n");
		}
	}

	for (int i = 0; i < data->length(); i++)
		Utils::ConsolePrint("%c", data->vector[i]);
	Utils::ConsolePrint("\n");

	return data;
}

void DisableVMP()
{
	// restore hook at NtProtectVirtualMemory
	DWORD old;
	VirtualProtect(NtProtectVirtualMemory, 1, PAGE_EXECUTE_READWRITE, &old);
	*(uintptr_t*)NtProtectVirtualMemory = *(uintptr_t*)NtQuerySection & ~(0xFFui64 << 32) | (uintptr_t)(*(uint32_t*)((uintptr_t)NtQuerySection + 4) - 1) << 32;
	VirtualProtect(NtProtectVirtualMemory, 1, old, &old);
}

void DisableLogReport()
{
	char szProcessPath[MAX_PATH]{};
	GetModuleFileNameA(nullptr, szProcessPath, MAX_PATH);

	auto path = std::filesystem::path(szProcessPath);
	auto ProcessName = path.filename().string();
	ProcessName = ProcessName.substr(0, ProcessName.find_last_of('.'));

	auto Astrolabe = path.parent_path() / (ProcessName + "_Data\\Plugins\\Astrolabe.dll");
	auto MiHoYoMTRSDK = path.parent_path() / (ProcessName + "_Data\\Plugins\\MiHoYoMTRSDK.dll");

	// open exclusive access to these two dlls
	// so they cannot be loaded
	HANDLE hFile = CreateFileA(Astrolabe.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
	hFile = CreateFileA(MiHoYoMTRSDK.string().c_str(), GENERIC_READ | GENERIC_WRITE, 0, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
}

uintptr_t FindEntry(uintptr_t addr)
{
	__try {
		while (true)
		{
			// walk back until we find function entry
			uint32_t code = *(uint32_t*)addr;
			code &= ~0xFF000000;

			if (_byteswap_ulong(code) == 0x4883EC00) // sub rsp, ??
				return addr;

			addr--;
		}
	}
	__except (1) {}

	return 0;
}

DWORD __stdcall Thread(LPVOID p)
{
	Utils::AttachConsole();
	Utils::ConsolePrint("Waiting for game to startup\n");

	auto pid = GetCurrentProcessId();
	while (true)
	{
		// use EnumWindows to pinpoint the target window
		// as there could be other window with the same class name
		EnumWindows([](HWND hwnd, LPARAM lParam) -> BOOL __stdcall {

			DWORD wndpid = 0;
			GetWindowThreadProcessId(hwnd, &wndpid);

			char szWindowClass[256]{};
			GetClassNameA(hwnd, szWindowClass, 256);
			if (!strcmp(szWindowClass, "UnityWndClass") && wndpid == *(DWORD*)lParam)
			{
				*(DWORD*)lParam = 0;
				return FALSE;
			}

			return TRUE;

		}, (LPARAM)&pid);

		if (!pid)
			break;

		Sleep(2000);
	}

	DisableVMP(); 
	auto GetPublicKey = Utils::PatternScan("UserAssembly.dll", "48 BA 45 78 70 6F 6E 65 6E 74 48 89 90 ? ? ? ? 48 BA 3E 3C 2F 52 53 41 4B 65"); // 'Exponent></RSAKe'
	auto GetPrivateKey = Utils::PatternScan("UserAssembly.dll", "2F 49 6E 76 65 72 73 65"); // '/Inverse'

	GetPublicKey = FindEntry(GetPublicKey);
	GetPrivateKey = FindEntry(GetPrivateKey);

	Utils::ConsolePrint("GetPublicKey: %p\n", GetPublicKey);
	Utils::ConsolePrint("GetPrivateKey: %p\n", GetPrivateKey);

	// check for null and alignment
	if (!GetPublicKey || GetPublicKey % 8 > 0)
		Utils::ConsolePrint("Failed to find GetPublicKey - Need to update\n");
	if (!GetPrivateKey || GetPrivateKey % 8 > 0)
		Utils::ConsolePrint("Failed to find GetPrivateKey - Need to update\n");

	oGetPublicKey = Detour((PVOID)GetPublicKey, hkGetRSAKey, true);
	oGetPrivateKey = Detour((PVOID)GetPrivateKey, hkGetRSAKey, true);

	Utils::ConsolePrint("Hooked GetPublicKey - Original at: %p\n", oGetPublicKey);
	Utils::ConsolePrint("Hooked GetPrivateKey - Original at: %p\n", oGetPrivateKey);

	return 0;
}

DWORD __stdcall DllMain(HINSTANCE hInstance, DWORD fdwReason, LPVOID lpReserved)
{
	if (hInstance)
		DisableThreadLibraryCalls(hInstance);

	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		if (HANDLE hThread = CreateThread(nullptr, 0, Thread, hInstance, 0, nullptr))
			CloseHandle(hThread);
	}

	return TRUE;
}

bool TlsOnce = false;
// this runs way before dllmain
void __stdcall TlsCallback(PVOID hModule, DWORD fdwReason, PVOID pContext)
{
	if (!TlsOnce)
	{
		DisableLogReport();
		// for version.dll proxy
		// load exports as early as possible
		// Utils::AttachConsole();
		Exports::Load();
		TlsOnce = true;
	}
}

#pragma comment (linker, "/INCLUDE:_tls_used")
#pragma comment (linker, "/INCLUDE:tls_callback_func")
#pragma const_seg(".CRT$XLF")
EXTERN_C const PIMAGE_TLS_CALLBACK tls_callback_func = TlsCallback;