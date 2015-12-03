using System;
using System.Runtime.InteropServices;

namespace RunPE_Shield.PE.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    public struct MODULE_INFO
    {
        public IntPtr lpBaseOfDll;
        public uint SizeOfImage;
        public IntPtr EntryPoint;
    }
}
