namespace VB3Decompiler.Disassembly;

/// <summary>
/// One decoded x86 instruction.
/// </summary>
public sealed class Instruction
{
    /// <summary>Offset of this instruction within its segment.</summary>
    public int Offset { get; init; }

    /// <summary>Raw bytes that make up this instruction.</summary>
    public byte[] Bytes { get; init; } = [];

    /// <summary>Mnemonic string (e.g. <c>"MOV"</c>, <c>"PUSH"</c>).</summary>
    public string Mnemonic { get; init; } = string.Empty;

    /// <summary>Operand string (may be empty for single-operand instructions).</summary>
    public string Operands { get; init; } = string.Empty;

    /// <summary>
    /// Returns the standard Intel-syntax disassembly line.
    /// Format: <c>OOOO  xx xx xx xx  MNEMONIC OPERANDS</c>
    /// </summary>
    public override string ToString()
    {
        string hexBytes = string.Join(" ", Bytes.Select(b => b.ToString("X2")));
        string ops = string.IsNullOrEmpty(Operands)
            ? Mnemonic
            : $"{Mnemonic,-8}{Operands}";
        return $"{Offset:X4}  {hexBytes,-14}  {ops}";
    }
}
