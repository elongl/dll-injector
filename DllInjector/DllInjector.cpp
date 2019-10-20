#include <Windows.h>
#include <iostream>
#include <filesystem>

void InjectDLL(DWORD pid, std::string dll_path)
{
	HANDLE target_proccess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
	if (target_proccess)
	{
		HMODULE kernel_module = GetModuleHandleA("kernel32.dll");
		if (kernel_module)
		{
			LPVOID load_library_addr = GetProcAddress(kernel_module, "LoadLibraryA");
			LPVOID load_path = VirtualAllocEx(target_proccess, NULL, dll_path.length(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
			if (load_path)
			{
				WriteProcessMemory(target_proccess, load_path, dll_path.c_str(), dll_path.length(), NULL);
				HANDLE remote_thread = CreateRemoteThread(target_proccess, NULL, 0, (LPTHREAD_START_ROUTINE)load_library_addr, load_path, 0, NULL);
				if (remote_thread)
				{
					WaitForSingleObject(remote_thread, INFINITE);
					std::cout << "DLL Injected successfully.";
					CloseHandle(remote_thread);
				}
				else
					std::cerr << "Failed to create remote thread on the target process.";
				VirtualFreeEx(target_proccess, load_path, 0, MEM_RELEASE);
			}
			else
				std::cerr << "Failed to allocate memory on the target process.";
			CloseHandle(target_proccess);
		}
		else
			std::cerr << "Failed to get kernel32.dll handle.";
	}
	else
		std::cerr << "Failed to open target process.";
}

unsigned int GetProcId(std::string window_name)
{
	DWORD pid;
	HWND window = FindWindowA(NULL, window_name.c_str());
	if (!window)
		throw std::exception("Failed to find window.");
	GetWindowThreadProcessId(window, &pid);
	return pid;
}

int main(int argc, char** argv)
{
	if (argc != 3)
		std::cout << "Usage: " << std::filesystem::path(argv[0]).filename().string() << " <Window Name> <DLL Path>";
	else
	{
		try { InjectDLL(GetProcId(argv[1]), argv[2]); }
		catch (std::exception & ex) { std::cerr << ex.what(); }
	}
}

