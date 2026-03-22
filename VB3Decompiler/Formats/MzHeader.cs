namespace VB3Decompiler.Formats;

/// <summary>
/// DOS MZ executable header (first 64 bytes of any NE/PE file).
/// </summary>
public sealed class MzHeader
{
    public const ushort MzMagic = 0x5A4D; // 'MZ'

    public ushort Magic { get; private set; }
    public ushort LastPageBytes { get; private set; }
    public ushort Pages { get; private set; }
    public ushort Relocations { get; private set; }
    public ushort HeaderParagraphs { get; private set; }
    public ushort MinAlloc { get; private set; }
    public ushort MaxAlloc { get; private set; }
    public ushort InitialSS { get; private set; }
    public ushort InitialSP { get; private set; }
    public ushort Checksum { get; private set; }
    public ushort InitialIP { get; private set; }
    public ushort InitialCS { get; private set; }
    public ushort RelocationOffset { get; private set; }
    public ushort OverlayNumber { get; private set; }

    /// <summary>Offset to the NE header (at MZ offset 0x3C).</summary>
    public uint NewHeaderOffset { get; private set; }

    public bool IsValid => Magic == MzMagic;

    public static MzHeader Read(BinaryReader reader)
    {
        var h = new MzHeader
        {
            Magic              = reader.ReadUInt16(), // 0x00
            LastPageBytes      = reader.ReadUInt16(), // 0x02
            Pages              = reader.ReadUInt16(), // 0x04
            Relocations        = reader.ReadUInt16(), // 0x06
            HeaderParagraphs   = reader.ReadUInt16(), // 0x08
            MinAlloc           = reader.ReadUInt16(), // 0x0A
            MaxAlloc           = reader.ReadUInt16(), // 0x0C
            InitialSS          = reader.ReadUInt16(), // 0x0E
            InitialSP          = reader.ReadUInt16(), // 0x10
            Checksum           = reader.ReadUInt16(), // 0x12
            InitialIP          = reader.ReadUInt16(), // 0x14
            InitialCS          = reader.ReadUInt16(), // 0x16
            RelocationOffset   = reader.ReadUInt16(), // 0x18
            OverlayNumber      = reader.ReadUInt16(), // 0x1A
        };

        reader.ReadBytes(4 * 2);  // e_res  [4 words] (0x1C–0x23)
        reader.ReadBytes(2);      // e_oemid          (0x24–0x25)
        reader.ReadBytes(2);      // e_oeminfo        (0x26–0x27)
        reader.ReadBytes(10 * 2); // e_res2 [10 words](0x28–0x3B)
        h.NewHeaderOffset = reader.ReadUInt32();      // 0x3C

        return h;
    }
}
