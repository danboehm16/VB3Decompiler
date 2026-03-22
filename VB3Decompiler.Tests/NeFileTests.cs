using System.Runtime.InteropServices;
using VB3Decompiler.Formats;

namespace VB3Decompiler.Tests;

/// <summary>
/// Tests for the NE file format parser using synthesised in-memory binaries.
/// </summary>
public class NeFileTests
{
    // -----------------------------------------------------------------------
    // Helpers
    // -----------------------------------------------------------------------

    /// <summary>
    /// Builds a minimal but valid NE binary in memory containing one code
    /// segment with the given <paramref name="segData"/>.
    /// </summary>
    private static byte[] BuildNeFile(byte[]? segData = null)
    {
        segData ??= [0x90]; // NOP

        // We'll lay the file out as:
        //   0x00 – 0x3F : MZ header (64 bytes)
        //   0x40 – 0x7F : NE header (64 bytes)
        //   0x80 – 0x87 : one segment table entry (8 bytes)
        //   0x88 …      : segment data (aligned to 0x100 / sector 1 with shift=9)

        // Sector 1 with align-shift 9 → file offset = 1 << 9 = 0x200
        const int neHeaderOffset  = 0x40;
        const int segTableRelOff  = 0x40; // relative to NE header start
        const int alignShift      = 9;
        const int segSector       = 1;    // → file offset 0x200
        const int segFileOffset   = segSector << alignShift; // 0x200

        int fileSize = segFileOffset + segData.Length;
        var buf = new byte[fileSize];

        // ---- MZ header ---------------------------------------------------
        buf[0] = 0x4D; buf[1] = 0x5A;      // 'MZ'
        // e_lfanew at offset 0x3C
        BitsHelper.WriteU32(buf, 0x3C, neHeaderOffset);

        // ---- NE header at 0x40 -------------------------------------------
        buf[neHeaderOffset + 0] = 0x4E;     // 'N'
        buf[neHeaderOffset + 1] = 0x45;     // 'E'
        buf[neHeaderOffset + 2] = 5;        // linker version
        buf[neHeaderOffset + 3] = 10;       // linker revision
        // ne_enttab (offset to entry table, relative to NE header) = 0x40 (skip past our seg table)
        BitsHelper.WriteU16(buf, neHeaderOffset + 0x04, segTableRelOff + 8);
        // ne_cbenttab = 0
        BitsHelper.WriteU16(buf, neHeaderOffset + 0x06, 0);
        // ne_flags: Windows compatible, single data segment
        BitsHelper.WriteU16(buf, neHeaderOffset + 0x0C, 0x0201);
        // ne_cseg = 1
        BitsHelper.WriteU16(buf, neHeaderOffset + 0x1C, 1);
        // ne_segtab (offset to segment table, relative to NE header) = segTableRelOff
        BitsHelper.WriteU16(buf, neHeaderOffset + 0x22, segTableRelOff);
        // ne_align = alignShift
        BitsHelper.WriteU16(buf, neHeaderOffset + 0x32, alignShift);
        // ne_exetyp = 2 (Windows)
        buf[neHeaderOffset + 0x36] = 2;

        // ---- Segment table entry at (neHeaderOffset + segTableRelOff) ----
        int segEntryBase = neHeaderOffset + segTableRelOff;
        BitsHelper.WriteU16(buf, segEntryBase + 0, segSector);              // ns_sector
        BitsHelper.WriteU16(buf, segEntryBase + 2, (ushort)segData.Length); // ns_cbseg
        BitsHelper.WriteU16(buf, segEntryBase + 4, 0x0000);                 // ns_flags: code seg
        BitsHelper.WriteU16(buf, segEntryBase + 6, (ushort)segData.Length); // ns_minalloc

        // ---- Segment data at 0x200 ----------------------------------------
        Array.Copy(segData, 0, buf, segFileOffset, segData.Length);

        return buf;
    }

    private static NeFile LoadFromBytes(byte[] bytes)
    {
        using var ms = new MemoryStream(bytes);
        using var reader = new BinaryReader(ms);
        return NeFile.Load(reader);
    }

    // -----------------------------------------------------------------------
    // MZ header tests
    // -----------------------------------------------------------------------

    [Fact]
    public void MzHeader_ReadsValidMagic()
    {
        var ne = LoadFromBytes(BuildNeFile());
        Assert.True(ne.Mz.IsValid);
        Assert.Equal(MzHeader.MzMagic, ne.Mz.Magic);
    }

    [Fact]
    public void MzHeader_NewHeaderOffset_IsCorrect()
    {
        var ne = LoadFromBytes(BuildNeFile());
        Assert.Equal(0x40u, ne.Mz.NewHeaderOffset);
    }

    [Fact]
    public void InvalidMzMagic_ThrowsInvalidDataException()
    {
        var bytes = BuildNeFile();
        bytes[0] = 0x00; // corrupt MZ magic
        Assert.Throws<InvalidDataException>(() => LoadFromBytes(bytes));
    }

    // -----------------------------------------------------------------------
    // NE header tests
    // -----------------------------------------------------------------------

    [Fact]
    public void NeHeader_ReadsValidMagic()
    {
        var ne = LoadFromBytes(BuildNeFile());
        Assert.True(ne.Ne.IsValid);
        Assert.Equal(NeHeader.NeMagic, ne.Ne.Magic);
    }

    [Fact]
    public void NeHeader_SegmentCount_IsOne()
    {
        var ne = LoadFromBytes(BuildNeFile());
        Assert.Equal(1, ne.Ne.SegmentCount);
    }

    [Fact]
    public void NeHeader_AlignShift_IsNine()
    {
        var ne = LoadFromBytes(BuildNeFile());
        Assert.Equal(9, ne.Ne.AlignShift);
    }

    [Fact]
    public void NeHeader_TargetOs_IsWindows()
    {
        var ne = LoadFromBytes(BuildNeFile());
        Assert.Equal(NeTargetOs.Windows, ne.Ne.TargetOs);
    }

    [Fact]
    public void InvalidNeSignature_ThrowsInvalidDataException()
    {
        var bytes = BuildNeFile();
        // Corrupt the NE magic at offset 0x40
        bytes[0x40] = 0x00;
        Assert.Throws<InvalidDataException>(() => LoadFromBytes(bytes));
    }

    // -----------------------------------------------------------------------
    // Segment table tests
    // -----------------------------------------------------------------------

    [Fact]
    public void Segments_Count_MatchesNeHeader()
    {
        var ne = LoadFromBytes(BuildNeFile());
        Assert.Equal(ne.Ne.SegmentCount, ne.Segments.Count);
    }

    [Fact]
    public void Segment_IsCode()
    {
        var ne = LoadFromBytes(BuildNeFile());
        Assert.True(ne.Segments[0].IsCode);
        Assert.False(ne.Segments[0].IsData);
    }

    [Fact]
    public void Segment_Data_IsLoaded()
    {
        byte[] payload = [0x55, 0x8B, 0xEC, 0x5D, 0xC3]; // PUSH BP / MOV BP,SP / POP BP / RET
        var ne = LoadFromBytes(BuildNeFile(payload));
        Assert.Equal(payload, ne.Segments[0].Data);
    }

    [Fact]
    public void Segment_FileOffset_IsCalculatedCorrectly()
    {
        var ne = LoadFromBytes(BuildNeFile());
        long expected = 1L << 9; // sector 1, shift 9 → 0x200
        Assert.Equal(expected, ne.Segments[0].GetFileOffset(9));
    }

    [Fact]
    public void Segment_GetActualSize_NonZero()
    {
        var ne = LoadFromBytes(BuildNeFile());
        Assert.Equal(1, ne.Segments[0].GetActualSize()); // payload is [0x90]
    }

    [Fact]
    public void Segment_GetActualSize_ZeroMeans64K()
    {
        // Build a NE file whose single segment has FileSize=0 (encodes 64 KiB).
        var bytes = BuildNeFile([0x90]);
        // Patch ns_cbseg (segment file size) to 0 to trigger the 64 KiB rule.
        // Segment entry starts at neHeaderOffset(0x40) + segTableRelOff(0x40) = 0x80.
        bytes[0x82] = 0x00; // ns_cbseg low byte
        bytes[0x83] = 0x00; // ns_cbseg high byte
        // Also fix ns_minalloc so the entry stays valid.
        bytes[0x86] = 0x00;
        bytes[0x87] = 0x00;
        var ne = LoadFromBytes(bytes);
        Assert.Equal(65536, ne.Segments[0].GetActualSize());
    }

    // -----------------------------------------------------------------------
    // NeFile.Load from path
    // -----------------------------------------------------------------------

    [Fact]
    public void Load_FromFilePath_Works()
    {
        byte[] payload = [0x90, 0xC3];
        string tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tmp, BuildNeFile(payload));
            var ne = NeFile.Load(tmp);
            Assert.True(ne.Mz.IsValid);
            Assert.True(ne.Ne.IsValid);
            Assert.Equal(payload, ne.Segments[0].Data);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    // -----------------------------------------------------------------------
    // DecompilerEngine integration
    // -----------------------------------------------------------------------

    [Fact]
    public void DecompilerEngine_Decompile_ProducesOutput()
    {
        byte[] payload = [0x55, 0x8B, 0xEC, 0x5D, 0xC3];
        string tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tmp, BuildNeFile(payload));
            var engine = new DecompilerEngine();
            using var sw = new StringWriter();
            engine.Decompile(tmp, sw);
            string output = sw.ToString();
            Assert.Contains("VB3Decompiler", output);
            Assert.Contains("PUSH", output);
            Assert.Contains("RET",  output);
        }
        finally
        {
            File.Delete(tmp);
        }
    }

    [Fact]
    public void DecompilerEngine_Decompile_NonNeFile_ThrowsDecompilerException()
    {
        string tmp = Path.GetTempFileName();
        try
        {
            File.WriteAllBytes(tmp, [0x00, 0x01, 0x02, 0x03]);
            var engine = new DecompilerEngine();
            using var sw = new StringWriter();
            Assert.Throws<DecompilerException>(() => engine.Decompile(tmp, sw));
        }
        finally
        {
            File.Delete(tmp);
        }
    }
}

/// <summary>Helper for writing little-endian values into a byte array.</summary>
internal static class BitsHelper
{
    public static void WriteU16(byte[] buf, int offset, ushort value)
    {
        buf[offset]     = (byte)(value & 0xFF);
        buf[offset + 1] = (byte)(value >> 8);
    }

    public static void WriteU32(byte[] buf, int offset, uint value)
    {
        buf[offset]     = (byte)(value & 0xFF);
        buf[offset + 1] = (byte)((value >> 8)  & 0xFF);
        buf[offset + 2] = (byte)((value >> 16) & 0xFF);
        buf[offset + 3] = (byte)((value >> 24) & 0xFF);
    }
}
