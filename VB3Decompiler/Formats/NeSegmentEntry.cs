namespace VB3Decompiler.Formats;

/// <summary>
/// Flags for a segment table entry (<c>ns_flags</c>).
/// </summary>
[Flags]
public enum NeSegmentFlags : ushort
{
    /// <summary>Data segment (bit 0 = 0 means code).</summary>
    DataSegment    = 0x0001,
    /// <summary>Segment is movable.</summary>
    Movable        = 0x0008,
    /// <summary>Segment is shareable.</summary>
    Shareable      = 0x0010,
    /// <summary>Segment is preloaded.</summary>
    Preloaded      = 0x0020,
    /// <summary>Execute-only (code) or Read-only (data).</summary>
    ExecuteOnly    = 0x0040,
    /// <summary>Segment has relocation records appended after its data.</summary>
    HasRelocs      = 0x0100,
    /// <summary>Segment is discardable.</summary>
    Discardable    = 0x1000,
}

/// <summary>
/// One entry in the NE segment table (8 bytes).
/// </summary>
public sealed class NeSegmentEntry
{
    /// <summary>
    /// Logical-sector offset in the file. Multiply by
    /// <c>1 &lt;&lt; ne_align</c> (the NE header's AlignShift) to get the
    /// byte offset.  A value of 0 means the segment is not present in the file.
    /// </summary>
    public ushort SectorOffset { get; private set; }

    /// <summary>
    /// Size of the segment in the file in bytes.  0 means 64 KiB.
    /// </summary>
    public ushort FileSize { get; private set; }

    /// <summary>Segment attribute flags.</summary>
    public NeSegmentFlags Flags { get; private set; }

    /// <summary>
    /// Minimum allocation size of the segment.  0 means 64 KiB.
    /// </summary>
    public ushort MinAlloc { get; private set; }

    /// <summary>True when the segment contains code (bit 0 of Flags is clear).</summary>
    public bool IsCode => (Flags & NeSegmentFlags.DataSegment) == 0;

    /// <summary>True when the segment contains data.</summary>
    public bool IsData => (Flags & NeSegmentFlags.DataSegment) != 0;

    /// <summary>
    /// Raw bytes loaded from the file (populated by <see cref="NeFile.Load"/>).
    /// </summary>
    public byte[] Data { get; internal set; } = [];

    public static NeSegmentEntry Read(BinaryReader reader) => new()
    {
        SectorOffset = reader.ReadUInt16(),
        FileSize     = reader.ReadUInt16(),
        Flags        = (NeSegmentFlags)reader.ReadUInt16(),
        MinAlloc     = reader.ReadUInt16(),
    };

    /// <summary>
    /// Returns the byte offset in the file given <paramref name="alignShift"/>
    /// (the NE header's AlignShift field).
    /// </summary>
    public long GetFileOffset(int alignShift) =>
        SectorOffset == 0 ? -1 : (long)SectorOffset << alignShift;

    /// <summary>
    /// Returns the actual size in bytes, resolving the "0 means 64 KiB" rule.
    /// </summary>
    public int GetActualSize() => FileSize == 0 ? 65536 : FileSize;
}
