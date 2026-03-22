using VB3Decompiler;

if (args.Length < 1)
{
    Console.Error.WriteLine("VB3Decompiler – disassembles 16-bit Visual Basic 3 / NE executables");
    Console.Error.WriteLine();
    Console.Error.WriteLine("Usage:");
    Console.Error.WriteLine("  VB3Decompiler <input.exe|.dll> [output.asm]");
    Console.Error.WriteLine();
    Console.Error.WriteLine("  input   - Path to a 16-bit NE executable (.exe, .dll, etc.)");
    Console.Error.WriteLine("  output  - Optional path to write the ASM output (default: stdout)");
    return 1;
}

string inputPath = args[0];
if (!File.Exists(inputPath))
{
    Console.Error.WriteLine($"Error: file not found: {inputPath}");
    return 2;
}

string? outputPath = args.Length >= 2 ? args[1] : null;

var engine = new DecompilerEngine();

try
{
    if (outputPath is not null)
    {
        using var writer = new StreamWriter(outputPath);
        engine.Decompile(inputPath, writer);
        Console.WriteLine($"Output written to: {outputPath}");
    }
    else
    {
        engine.Decompile(inputPath, Console.Out);
    }
    return 0;
}
catch (DecompilerException ex)
{
    Console.Error.WriteLine($"Error: {ex.Message}");
    return 3;
}
catch (IOException ex)
{
    Console.Error.WriteLine($"I/O error: {ex.Message}");
    return 4;
}
