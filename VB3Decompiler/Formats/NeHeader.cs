namespace VB3Decompiler.Formats;

/// <summary>
/// Flags field in the NE header (<c>ne_flags</c>).
/// </summary>
[Flags]
public enum NeHeaderFlags : ushort
{
    SingleDataSegment = 0x0001,
    MultipleDataSegments = 0x0002,
    GlobalInitialization = 0x0004,
    ProtectedMode = 0x0008,
    Instructions8086 = 0x0010,
    Instructions80286 = 0x0020,
    Instructions80386 = 0x0040,
    InstructionsFP = 0x0080,
    NotWindowsCompatible = 0x0100,
    WindowsCompatible = 0x0200,
    WindowsUsesAPI = 0x0300,
    FirstSegmentIsLoader = 0x0800,
    SelfLoading = 0x0800,
    LinkErrors = 0x2000,
    IsLibrary = 0x8000,
}

/// <summary>
/// Target operating system for the NE executable.
/// </summary>
public enum NeTargetOs : byte
{
    Unknown = 0,
    OS2 = 1,
    Windows = 2,
    Dos4 = 3,
    Windows386 = 4,
}

/// <summary>
/// NE (New Executable) header – the 16-bit Windows/OS2 format header.
/// Begins at the file offset stored in <see cref="MzHeader.NewHeaderOffset"/>.
/// </summary>
public sealed class NeHeader
{
    public const ushort NeMagic = 0x454E; // 'NE'

    // -- identity ----------------------------------------------------------
    public ushort Magic { get; private set; }
    public byte LinkerVersion { get; private set; }
    public byte LinkerRevision { get; private set; }

    // -- table offsets (relative to start of NE header) --------------------
    public ushort EntryTableOffset { get; private set; }
    public ushort EntryTableBytes { get; private set; }

    // -- misc fields -------------------------------------------------------
    public uint FileCrc { get; private set; }
    public NeHeaderFlags Flags { get; private set; }
    public ushort AutoDataSegment { get; private set; }
    public ushort InitialHeapSize { get; private set; }
    public ushort InitialStackSize { get; private set; }

    // -- entry point & stack -----------------------------------------------
    public ushort EntryIp { get; private set; }    // low word of CS:IP
    public ushort EntryCs { get; private set; }    // high word of CS:IP
    public ushort InitialSp { get; private set; }  // low word of SS:SP
    public ushort InitialSs { get; private set; }  // high word of SS:SP

    // -- counts ------------------------------------------------------------
    public ushort SegmentCount { get; private set; }
    public ushort ModuleReferenceCount { get; private set; }
    public ushort NonResidentNameTableSize { get; private set; }

    // -- more table offsets ------------------------------------------------
    public ushort SegmentTableOffset { get; private set; }
    public ushort ResourceTableOffset { get; private set; }
    public ushort ResidentNameTableOffset { get; private set; }
    public ushort ModuleReferenceTableOffset { get; private set; }
    public ushort ImportedNamesTableOffset { get; private set; }
    public uint NonResidentNameTableFileOffset { get; private set; }

    public ushort MovableEntryCount { get; private set; }
    public ushort AlignShift { get; private set; }
    public ushort ResourceCount { get; private set; }
    public NeTargetOs TargetOs { get; private set; }
    public byte OtherFlags { get; private set; }
    public ushort ReturnThunksOffset { get; private set; }
    public ushort SegmentRefBytesOffset { get; private set; }
    public ushort SwapAreaMinSize { get; private set; }
    public ushort ExpectedWindowsVersion { get; private set; }

    public bool IsValid => Magic == NeMagic;

    public static NeHeader Read(BinaryReader reader)
    {
        var h = new NeHeader
        {
            Magic                         = reader.ReadUInt16(), // +0x00
            LinkerVersion                 = reader.ReadByte(),   // +0x02
            LinkerRevision                = reader.ReadByte(),   // +0x03
            EntryTableOffset              = reader.ReadUInt16(), // +0x04
            EntryTableBytes               = reader.ReadUInt16(), // +0x06
            FileCrc                       = reader.ReadUInt32(), // +0x08
            Flags                         = (NeHeaderFlags)reader.ReadUInt16(), // +0x0C
            AutoDataSegment               = reader.ReadUInt16(), // +0x0E
            InitialHeapSize               = reader.ReadUInt16(), // +0x10
            InitialStackSize              = reader.ReadUInt16(), // +0x12
            EntryIp                       = reader.ReadUInt16(), // +0x14  CS:IP lo
            EntryCs                       = reader.ReadUInt16(), // +0x16  CS:IP hi
            InitialSp                     = reader.ReadUInt16(), // +0x18  SS:SP lo
            InitialSs                     = reader.ReadUInt16(), // +0x1A  SS:SP hi
            SegmentCount                  = reader.ReadUInt16(), // +0x1C
            ModuleReferenceCount          = reader.ReadUInt16(), // +0x1E
            NonResidentNameTableSize      = reader.ReadUInt16(), // +0x20
            SegmentTableOffset            = reader.ReadUInt16(), // +0x22
            ResourceTableOffset           = reader.ReadUInt16(), // +0x24
            ResidentNameTableOffset       = reader.ReadUInt16(), // +0x26
            ModuleReferenceTableOffset    = reader.ReadUInt16(), // +0x28
            ImportedNamesTableOffset      = reader.ReadUInt16(), // +0x2A
            NonResidentNameTableFileOffset= reader.ReadUInt32(), // +0x2C
            MovableEntryCount             = reader.ReadUInt16(), // +0x30
            AlignShift                    = reader.ReadUInt16(), // +0x32
            ResourceCount                 = reader.ReadUInt16(), // +0x34
            TargetOs                      = (NeTargetOs)reader.ReadByte(), // +0x36
            OtherFlags                    = reader.ReadByte(),   // +0x37
            ReturnThunksOffset            = reader.ReadUInt16(), // +0x38
            SegmentRefBytesOffset         = reader.ReadUInt16(), // +0x3A
            SwapAreaMinSize               = reader.ReadUInt16(), // +0x3C
            ExpectedWindowsVersion        = reader.ReadUInt16(), // +0x3E
        };
        return h;
    }
}
