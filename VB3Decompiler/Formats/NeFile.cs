namespace VB3Decompiler.Formats;

/// <summary>
/// Parses a 16-bit NE (New Executable) file – the format used by
/// Visual Basic 3 and other 16-bit Windows applications.
/// </summary>
public sealed class NeFile
{
    public MzHeader Mz { get; private set; } = null!;
    public NeHeader Ne { get; private set; } = null!;
    public IReadOnlyList<NeSegmentEntry> Segments { get; private set; } = [];

    /// <summary>
    /// Loads and parses the NE file at <paramref name="path"/>.
    /// </summary>
    /// <exception cref="InvalidDataException">
    /// Thrown when the file is not a valid MZ or NE executable.
    /// </exception>
    public static NeFile Load(string path)
    {
        using var stream = File.OpenRead(path);
        using var reader = new BinaryReader(stream);
        return Load(reader);
    }

    /// <summary>
    /// Loads and parses from a <see cref="BinaryReader"/> positioned at byte 0.
    /// The stream must be seekable.
    /// </summary>
    public static NeFile Load(BinaryReader reader)
    {
        var file = new NeFile();

        // ---- MZ header ---------------------------------------------------
        try
        {
            file.Mz = MzHeader.Read(reader);
        }
        catch (EndOfStreamException ex)
        {
            throw new InvalidDataException(
                "File is too small to contain a valid MZ header.", ex);
        }

        if (!file.Mz.IsValid)
            throw new InvalidDataException(
                "File does not begin with the MZ signature (not a valid DOS executable).");

        // ---- NE header ---------------------------------------------------
        reader.BaseStream.Seek(file.Mz.NewHeaderOffset, SeekOrigin.Begin);
        file.Ne = NeHeader.Read(reader);
        if (!file.Ne.IsValid)
            throw new InvalidDataException(
                "Expected NE signature at the new-executable header offset.  " +
                "The file may be a PE (32-bit) or LE/LX executable.");

        // ---- Segment table -----------------------------------------------
        long neBase = file.Mz.NewHeaderOffset;
        long segTableOffset = neBase + file.Ne.SegmentTableOffset;
        reader.BaseStream.Seek(segTableOffset, SeekOrigin.Begin);

        var segments = new List<NeSegmentEntry>(file.Ne.SegmentCount);
        for (int i = 0; i < file.Ne.SegmentCount; i++)
            segments.Add(NeSegmentEntry.Read(reader));

        // ---- Load segment data -------------------------------------------
        int alignShift = file.Ne.AlignShift == 0 ? 9 : file.Ne.AlignShift;
        foreach (var seg in segments)
        {
            long fileOffset = seg.GetFileOffset(alignShift);
            if (fileOffset < 0)
            {
                seg.Data = [];
                continue;
            }

            int size = seg.GetActualSize();
            reader.BaseStream.Seek(fileOffset, SeekOrigin.Begin);
            seg.Data = reader.ReadBytes(size);
        }

        file.Segments = segments;
        return file;
    }
}
