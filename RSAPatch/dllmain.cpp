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
EXTERN_C NTSTATUS __stdcall NtPulseEvent(HANDLE EventHandle, PULONG PreviousState);

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

class String
{
public:
	void* klass;
	void* monitor;
	uint32_t length;
	wchar_t chars[];

	wchar_t* c_str() {
		return chars;
	}

	size_t size() {
		return length;
	}
};


PVOID oGetPublicKey = nullptr;
PVOID oGetPrivateKey = nullptr;
PVOID oReadToEnd = nullptr;
LPCSTR gcpb = "<RSAKeyValue><Modulus>xbbx2m1feHyrQ7jP+8mtDF/pyYLrJWKWAdEv3wZrOtjOZzeLGPzsmkcgncgoRhX4dT+1itSMR9j9m0/OwsH2UoF6U32LxCOQWQD1AMgIZjAkJeJvFTrtn8fMQ1701CkbaLTVIjRMlTw8kNXvNA/A9UatoiDmi4TFG6mrxTKZpIcTInvPEpkK2A7Qsp1E4skFK8jmysy7uRhMaYHtPTsBvxP0zn3lhKB3W+HTqpneewXWHjCDfL7Nbby91jbz5EKPZXWLuhXIvR1Cu4tiruorwXJxmXaP1HQZonytECNU/UOzP6GNLdq0eFDE4b04Wjp396551G99YiFP2nqHVJ5OMQ==</Modulus><Exponent>AQAB</Exponent></RSAKeyValue>";

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
	std::ifstream ifs(std::filesystem::current_path() / path);
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
		if (customKey.empty())
		{
			Utils::ConsolePrint("using grasscutter public key\n");
			customKey = gcpb;
		}
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

String* __fastcall hkReadToEnd(void* rcx, void* rdx)
{
	auto result = decltype(&hkReadToEnd)(oReadToEnd)(rcx, rdx);
	if (!result)
		return result;

	if (!wcsstr(result->c_str(), L"<RSAKeyValue>"))
		return result;

	bool isPrivate = wcsstr(result->c_str(), L"<InverseQ>");
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
		if (customKey.empty())
		{
			Utils::ConsolePrint("original:\n");
			Utils::ConsolePrint("%S\n\n", result->c_str());

			Utils::ConsolePrint("using grasscutter public key\n");
			customKey = gcpb;
		}
	}

	if (!customKey.empty())
	{
		if (customKey.size() <= result->size())
		{
			ZeroMemory(result->chars, result->size() * 2);
			std::wstring wstr = std::wstring(customKey.begin(), customKey.end()); // idc
			memcpy_s(result->chars, result->size() * 2, wstr.data(), wstr.size() * 2);
		}
		else
		{
			Utils::ConsolePrint("custom key longer than original\n");
		}
	}

	for (int i = 0; i < result->size(); i++)
		Utils::ConsolePrint("%C", result->chars[i]);
	Utils::ConsolePrint("\n\n");

	return result;
}

void DisableVMP()
{
	// restore hook at NtProtectVirtualMemory
	auto ntdll = GetModuleHandleA("ntdll.dll");
	bool linux = GetProcAddress(ntdll, "wine_get_version") != nullptr;
	void* routine = linux ? (void*)NtPulseEvent : (void*)NtQuerySection;
	DWORD old;
	VirtualProtect(NtProtectVirtualMemory, 1, PAGE_EXECUTE_READWRITE, &old);
	*(uintptr_t*)NtProtectVirtualMemory = *(uintptr_t*)routine & ~(0xFFui64 << 32) | (uintptr_t)(*(uint32_t*)((uintptr_t)routine + 4) - 1) << 32;
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

void OldVersion() // <= 3.5.0 
{
	auto GetPublicKey = Utils::PatternScan("UserAssembly.dll", "48 BA 45 78 70 6F 6E 65 6E 74 48 89 90 ? ? ? ? 48 BA 3E 3C 2F 52 53 41 4B 65"); // 'Exponent></RSAKe'
	auto GetPrivateKey = Utils::PatternScan("UserAssembly.dll", "2F 49 6E 76 65 72 73 65"); // '/Inverse'

	GetPublicKey = FindEntry(GetPublicKey);
	GetPrivateKey = FindEntry(GetPrivateKey);

	Utils::ConsolePrint("GetPublicKey: %p\n", GetPublicKey);
	Utils::ConsolePrint("GetPrivateKey: %p\n", GetPrivateKey);

	// check for null and alignment
	if (!GetPublicKey || GetPublicKey % 16 > 0)
		Utils::ConsolePrint("Failed to find GetPublicKey - Need to update\n");
	if (!GetPrivateKey || GetPrivateKey % 16 > 0)
		Utils::ConsolePrint("Failed to find GetPrivateKey - Need to update\n");

	oGetPublicKey = Detour((PVOID)GetPublicKey, hkGetRSAKey, true);
	oGetPrivateKey = Detour((PVOID)GetPrivateKey, hkGetRSAKey, true);

	Utils::ConsolePrint("Hooked GetPublicKey - Original at: %p\n", oGetPublicKey);
	Utils::ConsolePrint("Hooked GetPrivateKey - Original at: %p\n", oGetPrivateKey);
}

void ACheckForThoseWhoCannotFollowInstructions(LPVOID instance)
{
	if (!instance)
	{
		// this shouldn't happen
		return;
	}

	char szModulePath[MAX_PATH]{};
	GetModuleFileNameA((HMODULE)instance, szModulePath, MAX_PATH);
	
	std::filesystem::path ModulePath = szModulePath;
	std::string ModuleName = ModulePath.filename().string();
	std::transform(ModuleName.begin(), ModuleName.end(), ModuleName.begin(), ::tolower);

	if (ModuleName == "version.dll")
	{
		// check mhypbase.dll
		auto mhypbase = GetModuleHandleA("mhypbase.dll");
		if (!mhypbase)
			return;

		PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)mhypbase;
		PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((uintptr_t)mhypbase + dosHeader->e_lfanew);
		auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
		
		// over 1MB
		if (sizeOfImage > 1 * 1024 * 1024) 
			return;

		// uh oh
	}
	else
	{
		// check version.dll
		auto version = GetModuleHandleA("version.dll");
		if (!version)
			return; // this shouldn't happen

		ZeroMemory(szModulePath, MAX_PATH);
		GetModuleFileNameA((HMODULE)version, szModulePath, MAX_PATH);
		ModuleName = szModulePath;
		std::transform(ModuleName.begin(), ModuleName.end(), ModuleName.begin(), ::tolower);

		if (ModuleName.find("system32") != std::string::npos)
			return;

		// uh oh
	}

	// https://www.youtube.com/watch?v=9a_3wQHcm_Y
	MessageBoxA(nullptr, "You may have more than one RSAPatch installed.\nPlease only use one RSAPatch to avoid instability.", "RSAPatch", MB_ICONWARNING);
}

DWORD __stdcall Thread(LPVOID p)
{
	Utils::AttachConsole();
	Utils::ConsolePrint("Waiting for game to startup\n");

	ACheckForThoseWhoCannotFollowInstructions(p);

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
	
	auto UserAssembly = (uintptr_t)GetModuleHandleA("UserAssembly.dll");
	PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)UserAssembly;
	PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)(UserAssembly + dos->e_lfanew);
	DWORD timestamp = nt->FileHeader.TimeDateStamp;

	if (timestamp <= 0x63ECA960)
	{
		OldVersion();
		return 0;
	}

	auto ReadToEnd = Utils::PatternScan("UserAssembly.dll", "48 89 5C 24 ? 48 89 74 24 ? 48 89 7C 24 ? 41 56 48 83 EC 20 48 83 79 ? ? 48 8B D9 75 05");
	Utils::ConsolePrint("ReadToEnd: %p\n", ReadToEnd);

	if (!ReadToEnd || ReadToEnd % 16 > 0)
		Utils::ConsolePrint("Failed to find ReadToEnd - Need to update\n");

	oReadToEnd = Detour((PVOID)ReadToEnd, hkReadToEnd, true);
	Utils::ConsolePrint("Hooked ReadToEnd - Original at: %p\n", oReadToEnd);

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
