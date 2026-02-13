// dllmain.cpp : 定义 DLL 应用程序的入口点。
#include "pch.h"
#include <Windows.h>
#include <string>
#include <cstdint>
#include <TlHelp32.h>

// 定义导出宏
#define DLL_INJECTOR_API __declspec(dllexport)

// --- C++ 内部使用的枚举和函数 ---

// 定义一个简单的枚举来表示注入结果
enum class InjectResult
{
    Success,
    ProcessNotFound,
    ProcessOpenFailed,
    MemoryAllocationFailed,
    WriteMemoryFailed,
    CreateRemoteThreadFailed,
    GetProcAddressFailed,
    InvalidDllPath
};

// C++ 内部实现，使用 std::string
InjectResult _DLLInject_cpp(const std::string& dllPath, const std::string& processName);
DWORD _GetProcessIdByName_cpp(const std::string& processName);

// --- C# 要调用的 C 接口 ---

// 定义一个可以被 C# 理解的 C 风格枚举
typedef enum {
    InjectResult_Success = 0,
    InjectResult_ProcessNotFound = 1,
    InjectResult_ProcessOpenFailed = 2,
    InjectResult_MemoryAllocationFailed = 3,
    InjectResult_WriteMemoryFailed = 4,
    InjectResult_CreateRemoteThreadFailed = 5,
    InjectResult_GetProcAddressFailed = 6,
    InjectResult_InvalidDllPath = 7
} InjectResult_C;

// 声明并实现导出的 C 函数
extern "C" {
    // 获取进程ID的包装函数
    DLL_INJECTOR_API uint32_t WINAPI GetProcessIdByName(const char* processName);

    // DLL注入的包装函数
    DLL_INJECTOR_API InjectResult_C WINAPI DLLInject(const char* dllPath, const char* processName);
}


// --- DLL 入口点 (无需改动) ---
BOOL APIENTRY DllMain(HMODULE hModule,
    DWORD ul_reason_for_call,
    LPVOID lpReserved)
{
    switch (ul_reason_for_call)
    {
    case DLL_PROCESS_ATTACH:
    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
    case DLL_PROCESS_DETACH:
        break;
    }
    return TRUE;
}

// --- C# 调用的包装函数的实现 ---

extern "C" {
    DLL_INJECTOR_API uint32_t WINAPI GetProcessIdByName(const char* processName)
    {
        // 将 C 字符串转换为 C++ std::string
        std::string strProcessName(processName);

        // 调用 C++ 内部实现
        DWORD processId = _GetProcessIdByName_cpp(strProcessName);

        // 返回结果
        return static_cast<uint32_t>(processId);
    }

    DLL_INJECTOR_API InjectResult_C WINAPI DLLInject(const char* dllPath, const char* processName)
    {
        // 将 C 字符串转换为 C++ std::string
        std::string cppDllPath(dllPath);
        std::string cppProcessName(processName);

        // 调用 C++ 内部实现
        InjectResult cppResult = _DLLInject_cpp(cppDllPath, cppProcessName);

        // 将 C++ 枚举结果转换为 C 枚举结果
        InjectResult_C cResult;
        switch (cppResult)
        {
        case InjectResult::Success:                   cResult = InjectResult_Success; break;
        case InjectResult::ProcessNotFound:           cResult = InjectResult_ProcessNotFound; break;
        case InjectResult::ProcessOpenFailed:         cResult = InjectResult_ProcessOpenFailed; break;
        case InjectResult::MemoryAllocationFailed:    cResult = InjectResult_MemoryAllocationFailed; break;
        case InjectResult::WriteMemoryFailed:         cResult = InjectResult_WriteMemoryFailed; break;
        case InjectResult::CreateRemoteThreadFailed:  cResult = InjectResult_CreateRemoteThreadFailed; break;
        case InjectResult::GetProcAddressFailed:      cResult = InjectResult_GetProcAddressFailed; break;
        case InjectResult::InvalidDllPath:            cResult = InjectResult_InvalidDllPath; break;
        default:                                      cResult = InjectResult_ProcessOpenFailed; break; // 默认错误
        }

        // 返回 C 风格的结果
        return cResult;
    }
}


// --- C++ 内部函数的实现 (修复后的逻辑) ---

static DWORD _GetProcessIdByName_cpp(const std::string& processName)
{
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return 0;
    if (!Process32First(hSnapshot, &pe32)) { CloseHandle(hSnapshot); return 0; }

    do {
        // 使用宽字符比较
        std::wstring wCurrentProcessName(pe32.szExeFile);
        std::string currentProcessName;

        // 正确转换宽字符到多字节字符
        int size_needed = WideCharToMultiByte(CP_UTF8, 0, &wCurrentProcessName[0], (int)wCurrentProcessName.size(), NULL, 0, NULL, NULL);
        currentProcessName = std::string(size_needed, 0);
        WideCharToMultiByte(CP_UTF8, 0, &wCurrentProcessName[0], (int)wCurrentProcessName.size(), &currentProcessName[0], size_needed, NULL, NULL);

        if (processName == currentProcessName) {
            CloseHandle(hSnapshot);
            return pe32.th32ProcessID;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return 0;
}


InjectResult _DLLInject_cpp(const std::string& dllPath, const std::string& processName)
{
    // 添加DLL路径验证
    if (GetFileAttributesA(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        return InjectResult::InvalidDllPath;
    }

    DWORD processId = _GetProcessIdByName_cpp(processName);
    if (processId == 0) return InjectResult::ProcessNotFound;

    HANDLE hProcess = OpenProcess(PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) return InjectResult::ProcessOpenFailed;

    size_t pathSize = dllPath.length() + 1;
    // 修复1: 将 PAGE_EXECUTE_READWRITE 改为 PAGE_READWRITE
    LPVOID pRemoteMemory = VirtualAllocEx(hProcess, NULL, pathSize, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pRemoteMemory == NULL) { CloseHandle(hProcess); return InjectResult::MemoryAllocationFailed; }

    if (!WriteProcessMemory(hProcess, pRemoteMemory, dllPath.c_str(), pathSize, NULL))
    {
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return InjectResult::WriteMemoryFailed;
    }

    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    if (hKernel32 == NULL) {
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return InjectResult::GetProcAddressFailed;
    }

    LPVOID pLoadLibraryA = GetProcAddress(hKernel32, "LoadLibraryA");
    if (pLoadLibraryA == NULL) {
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return InjectResult::GetProcAddressFailed;
    }

    HANDLE hRemoteThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pLoadLibraryA, pRemoteMemory, 0, NULL);
    if (hRemoteThread == NULL) {
        VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return InjectResult::CreateRemoteThreadFailed;
    }

    // 修复2: 等待远程线程完成后再释放内存
    WaitForSingleObject(hRemoteThread, INFINITE);

    // 7. 清理资源
    CloseHandle(hRemoteThread);
    VirtualFreeEx(hProcess, pRemoteMemory, 0, MEM_RELEASE);
    CloseHandle(hProcess);

    return InjectResult::Success;
}
