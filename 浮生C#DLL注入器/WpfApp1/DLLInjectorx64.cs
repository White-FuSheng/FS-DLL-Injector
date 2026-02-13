using System;
using System.Runtime.InteropServices;

public static class NativeInjector64
{
    // 🔑 声明 DLL 的名称
    // 确保这个名称与你复制到输出目录的 DLL 文件名完全一致
    private const string DllName = "InjectorDLLx64.dll";

    // 🔑 声明与 C++ 对应的枚举
    // C++ 的 typedef enum 默认是 int，所以 C# 的 enum 默认也是 int，完美匹配
    public enum InjectResult
    {
        Success = 0,
        ProcessNotFound = 1,
        ProcessOpenFailed = 2,
        MemoryAllocationFailed = 3,
        WriteMemoryFailed = 4,
        CreateRemoteThreadFailed = 5,
        GetProcAddressFailed = 6,
        InvalidDllPath = 7
    }

    // 🔑 声明 GetProcessIdByName 函数
    [DllImport(DllName, EntryPoint = "GetProcessIdByName", CallingConvention = CallingConvention.StdCall)]
    public static extern uint GetProcessIdByName(
        [MarshalAs(UnmanagedType.LPStr)] string processName
    );

    // 🔑 声明 DLLInject 函数
    [DllImport(DllName, EntryPoint = "DLLInject", CallingConvention = CallingConvention.StdCall)]
    public static extern InjectResult DLLInject(
        [MarshalAs(UnmanagedType.LPStr)] string dllPath,
        [MarshalAs(UnmanagedType.LPStr)] string processName
    );
}
