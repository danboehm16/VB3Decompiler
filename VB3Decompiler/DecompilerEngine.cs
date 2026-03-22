using VB3Decompiler.Disassembly;
using VB3Decompiler.Formats;

namespace VB3Decompiler;

/// <summary>
/// Orchestrates loading a 16-bit NE executable and disassembling its code
/// segments to x86 assembly text.
/// </summary>
public sealed class DecompilerEngine
{
    private readonly X86Disassembler _disassembler = new();

    /// <summary>
    /// Decompiles the file at <paramref name="filePath"/> and writes
    /// Intel-syntax ASM to <paramref name="output"/>.
    /// </summary>
    public void Decompile(string filePath, TextWriter output)
    {
        NeFile ne;
        try
        {
            ne = NeFile.Load(filePath);
        }
        catch (InvalidDataException ex)
        {
            throw new DecompilerException(
                $"'{filePath}' is not a valid 16-bit NE executable: {ex.Message}", ex);
        }

        output.WriteLine("; VB3Decompiler – 16-bit NE executable disassembly");
        output.WriteLine($"; File   : {Path.GetFileName(filePath)}");
        output.WriteLine($"; Target : {ne.Ne.TargetOs}");
        output.WriteLine($"; Flags  : {ne.Ne.Flags}");
        output.WriteLine($"; Segs   : {ne.Segments.Count}");
        output.WriteLine();

        for (int i = 0; i < ne.Segments.Count; i++)
        {
            var seg = ne.Segments[i];
            string segType = seg.IsCode ? "CODE" : "DATA";
            output.WriteLine($"; ---- Segment {i + 1} ({segType}) ----");
            output.WriteLine($"; Flags: {seg.Flags}");
            output.WriteLine($"; Size : {seg.Data.Length} bytes");
            output.WriteLine();

            if (seg.IsCode && seg.Data.Length > 0)
            {
                DisassembleSegment(seg.Data, output);
            }
            else if (seg.IsData && seg.Data.Length > 0)
            {
                DumpDataSegment(seg.Data, output);
            }
            else
            {
                output.WriteLine("; (empty or not present in file)");
            }

            output.WriteLine();
        }
    }

    // -----------------------------------------------------------------------

    private void DisassembleSegment(byte[] code, TextWriter output)
    {
        var instructions = _disassembler.Disassemble(code, startOffset: 0);
        foreach (var instr in instructions)
            output.WriteLine(instr.ToString());
    }

    private static void DumpDataSegment(byte[] data, TextWriter output)
    {
        const int bytesPerLine = 16;
        for (int i = 0; i < data.Length; i += bytesPerLine)
        {
            int count = Math.Min(bytesPerLine, data.Length - i);
            string hex   = string.Join(" ", data.Skip(i).Take(count).Select(b => b.ToString("X2")));
            string ascii = new string(
                data.Skip(i).Take(count).Select(b => b is >= 0x20 and < 0x7F ? (char)b : '.').ToArray());
            output.WriteLine($"{i:X4}  {hex,-47}  {ascii}");
        }
    }
}

/// <summary>
/// Thrown when the decompiler encounters an unrecoverable error.
/// </summary>
public sealed class DecompilerException : Exception
{
    public DecompilerException(string message, Exception? inner = null)
        : base(message, inner) { }
}
