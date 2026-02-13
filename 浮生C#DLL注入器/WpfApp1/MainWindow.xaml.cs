using System;
using System.IO;
using System.Windows;
using System.Windows.Input;
using Microsoft.Win32;
using System.Diagnostics;
using System.Runtime.InteropServices; // P/Invoke 需要

namespace WpfApp1
{
    public partial class MainWindow : Window
    {
        public MainWindow()
        {
            InitializeComponent();
        }

        private void TextBox_MouseDoubleClick(object sender, MouseButtonEventArgs e)
        {
            OpenFileDialog openFileDialog = new OpenFileDialog();
            openFileDialog.Title = "请选择一个DLL文件";
            openFileDialog.Filter = "DLL 文件 (*.dll)|*.dll";
            if (openFileDialog.ShowDialog() == true)
            {
                FilePathTextBox.Text = openFileDialog.FileName;
            }
        }

        private void Button_PreviewMouseLeftButtonDown(object sender, MouseButtonEventArgs e)
        {
            // 1. 基本输入验证
            if (string.IsNullOrEmpty(FilePathTextBox.Text) || string.IsNullOrEmpty(InjectedGameName.Text))
            {
                MessageBox.Show("DLL路径和进程名不能为空！", "输入错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            if (!File.Exists(FilePathTextBox.Text))
            {
                MessageBox.Show("选择的DLL文件不存在！", "文件错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            string dllPath = FilePathTextBox.Text;
            string processName = InjectedGameName.Text;

            // 2. 查找目标进程
            Process[] targetProcesses = Process.GetProcessesByName(Path.GetFileNameWithoutExtension(processName));
            if (targetProcesses.Length == 0)
            {
                MessageBox.Show($"未找到目标进程: {processName}", "进程错误", MessageBoxButton.OK, MessageBoxImage.Warning);
                return;
            }

            Process targetProcess = targetProcesses[0];
            int processId = targetProcess.Id;
            // 关闭进程句柄，避免占用
            foreach (var p in targetProcesses) p.Close();

            // 3. 准确判断目标进程是32位还是64位
            bool isTarget64Bit;
            try
            {
                isTarget64Bit = IsProcess64Bit(processId);
            }
            catch (Exception ex)
            {
                MessageBox.Show($"无法判断目标进程的架构。\n详情: {ex.Message}\n\n请尝试以管理员身份运行此程序。", "架构检测错误", MessageBoxButton.OK, MessageBoxImage.Error);
                return;
            }

            // 4. 检查注入器与目标进程的架构是否匹配
            bool isInjector64Bit = Environment.Is64BitProcess;
            if (isInjector64Bit == isTarget64Bit)
            {
                // 架构匹配，执行注入
                PerformInjection(dllPath, processName, isTarget64Bit);
            }
            else
            {
                // 架构不匹配
                string injectorArch = isInjector64Bit ? "64位" : "32位";
                string targetArch = isTarget64Bit ? "64位" : "32位";
                MessageBox.Show($"架构不匹配！\n你的注入器是 {injectorArch}，但目标进程是 {targetArch}。\n请使用对应架构版本的注入器。", "架构错误", MessageBoxButton.OK, MessageBoxImage.Error);
            }
        }

        /// <summary>
        /// 使用 Windows API 准确判断进程是否为64位
        /// </summary>
        [DllImport("kernel32.dll", SetLastError = true, CallingConvention = CallingConvention.StdCall)]
        private static extern bool IsWow64Process(IntPtr hProcess, out bool wow64Process);

        [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
        private static extern IntPtr OpenProcess(ProcessAccessFlags dwDesiredAccess, bool bInheritHandle, int dwProcessId);

        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern bool CloseHandle(IntPtr hObject);

        [Flags]
        private enum ProcessAccessFlags : uint
        {
            QueryInformation = 0x00000400,
            VMRead = 0x00000010,
            VMWrite = 0x00000020,
            VMOperation = 0x00000008,
            All = 0x001F0FFF
        }

        private bool IsProcess64Bit(int processId)
        {
            // 如果本机不是64位系统，那么所有进程都是32位的
            if (!Environment.Is64BitOperatingSystem)
            {
                return false;
            }

            IntPtr hProcess = OpenProcess(ProcessAccessFlags.QueryInformation, false, processId);
            if (hProcess == IntPtr.Zero)
            {
                throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
            }

            try
            {
                bool isWow64;
                // IsWow64Process 函数在64位进程上调用时，如果目标进程是32位，返回true；如果目标进程是64位，返回false。
                if (!IsWow64Process(hProcess, out isWow64))
                {
                    throw new System.ComponentModel.Win32Exception(Marshal.GetLastWin32Error());
                }

                // 在64位系统上，IsWow64Process 为 false 的进程就是64位进程。
                return !isWow64;
            }
            finally
            {
                CloseHandle(hProcess);
            }
        }


        /// <summary>
        /// 执行注入操作
        /// </summary>
        private void PerformInjection(string dllPath, string processName, bool is64Bit)
        {
            int resultCode;
            if (is64Bit)
            {
                NativeInjector64.InjectResult result = NativeInjector64.DLLInject(dllPath, processName);
                resultCode = (int)result;
            }
            else
            {
                NativeInjector32.InjectResult result = NativeInjector32.DLLInject(dllPath, processName);
                resultCode = (int)result;
            }
            ShowInjectionResult(resultCode);
        }

        /// <summary>
        /// 显示注入结果
        /// </summary>
        private void ShowInjectionResult(int resultCode)
        {
            string message;
            switch (resultCode)
            {
                case 0: message = "注入成功!"; break;
                case 1: message = "注入失败: 未找到进程。"; break;
                case 2: message = "注入失败: 无法打开进程（可能需要管理员权限）。"; break;
                case 3: message = "注入失败: 内存分配失败。"; break;
                case 4: message = "注入失败: 写入内存失败。"; break;
                case 5: message = "注入失败: 创建远程线程失败。"; break;
                case 6: message = "注入失败: 获取系统API地址失败。"; break;
                case 7: message = "注入失败: DLL路径无效。"; break;
                default: message = $"注入失败: 未知错误 (代码: {resultCode})。"; break;
            }

            MessageBoxImage icon = (resultCode == 0) ? MessageBoxImage.Information : MessageBoxImage.Error;
            MessageBox.Show(message, (resultCode == 0) ? "操作成功" : "注入失败", MessageBoxButton.OK, icon);
        }
    }
}
