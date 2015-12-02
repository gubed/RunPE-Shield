using System.Runtime.InteropServices;

namespace RunPE_Shield.PE.Structures
{
    [StructLayout(LayoutKind.Sequential)]
    public struct IMAGE_DATA_DIRECTORIES
    {
        public uint ExportTableRva;
        public uint SizeOfExportTable;
        public uint ImportTableRva;
        public uint SizeOfImportTable;
        public uint ResourceTableRva;
        public uint SizeOfResourceTable;
        public uint ExceptionTableRva;
        public uint SizeOfExceptionTable;
        public uint CertificateTableRva;
        public uint SizeOfSertificateTable;
        public uint BaseRelocationTable;
        public uint SizeOfBaseRelocation;
        public uint DebugRva;
        public uint SizeOfDebug;
        public uint ArchitechureRva;
        public uint SizeOfArchitechure;
        public uint GlobalPtrRva;
        public uint SizeOfGlobalPointer;
        public uint TLSTable;
        public uint SizeOfTLSTable;
        public uint LoadConfigTableRva;
        public uint SizeOfLoadConfigTable;
        public uint BoundImportRva;
        public uint SizeOfBoundImport;
        public uint ImportAddressTableRva;
        public uint SizeOfImportAddressTable;
        public uint DelayImportDescriptorRva;
        public uint SizeOfDelayImportDescriptor;
        public uint CLRRuntimeHeaderRva;
        public uint SizeOfCLRRumtimeHeader;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst=8)]
        private byte[] Null;
    }
}
