namespace VB3Decompiler.Disassembly;

/// <summary>
/// Disassembles 16-bit x86 (8086/80286) machine code to a list of
/// <see cref="Instruction"/> objects using Intel syntax.
/// </summary>
public sealed class X86Disassembler
{
    // -----------------------------------------------------------------------
    // Register name tables
    // -----------------------------------------------------------------------

    private static readonly string[] Reg8  = ["AL", "CL", "DL", "BL", "AH", "CH", "DH", "BH"];
    private static readonly string[] Reg16 = ["AX", "CX", "DX", "BX", "SP", "BP", "SI", "DI"];
    private static readonly string[] RegSeg = ["ES", "CS", "SS", "DS"];

    // -----------------------------------------------------------------------
    // ModRM effective-address strings (Mod 00/01/10, R/M 0..7)
    // -----------------------------------------------------------------------

    private static readonly string[] RmBase =
    [
        "BX+SI", "BX+DI", "BP+SI", "BP+DI", "SI", "DI", "BP", "BX"
    ];

    // -----------------------------------------------------------------------
    // Public entry point
    // -----------------------------------------------------------------------

    /// <summary>
    /// Disassembles <paramref name="code"/> starting at
    /// <paramref name="startOffset"/> (used only for instruction address labels).
    /// </summary>
    public IReadOnlyList<Instruction> Disassemble(byte[] code, int startOffset = 0)
    {
        var instructions = new List<Instruction>();
        int pos = 0;

        while (pos < code.Length)
        {
            int instrStart = pos;
            try
            {
                var instr = DecodeOne(code, ref pos, startOffset + instrStart);
                instructions.Add(instr);
            }
            catch (IndexOutOfRangeException)
            {
                // Truncated instruction at end of segment – emit a DB directive.
                instructions.Add(new Instruction
                {
                    Offset   = startOffset + instrStart,
                    Bytes    = [code[instrStart]],
                    Mnemonic = "DB",
                    Operands = $"0x{code[instrStart]:X2}",
                });
                pos = instrStart + 1;
            }
        }

        return instructions;
    }

    // -----------------------------------------------------------------------
    // Internal decode helpers
    // -----------------------------------------------------------------------

    private Instruction DecodeOne(byte[] code, ref int pos, int address)
    {
        int start = pos;

        // Collect prefixes
        string? segOverride = null;
        bool repPrefix    = false;
        bool repnePrefix  = false;
        bool lockPrefix   = false;

        while (true)
        {
            byte b = Peek(code, pos);
            switch (b)
            {
                case 0x26: segOverride = "ES"; pos++; continue;
                case 0x2E: segOverride = "CS"; pos++; continue;
                case 0x36: segOverride = "SS"; pos++; continue;
                case 0x3E: segOverride = "DS"; pos++; continue;
                case 0xF0: lockPrefix  = true;  pos++; continue;
                case 0xF2: repnePrefix = true;  pos++; continue;
                case 0xF3: repPrefix   = true;  pos++; continue;
            }
            break;
        }

        byte op = Read8(code, ref pos);

        string mnemo;
        string operands;

        switch (op)
        {
            // ----------------------------------------------------------------
            // ADD  r/m, r
            case 0x00: (mnemo, operands) = AluRmR(code, ref pos, "ADD", w: false, segOverride); break;
            case 0x01: (mnemo, operands) = AluRmR(code, ref pos, "ADD", w: true,  segOverride); break;
            // ADD  r, r/m
            case 0x02: (mnemo, operands) = AluRRm(code, ref pos, "ADD", w: false, segOverride); break;
            case 0x03: (mnemo, operands) = AluRRm(code, ref pos, "ADD", w: true,  segOverride); break;
            // ADD  AL/AX, imm
            case 0x04: (mnemo, operands) = ("ADD", $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0x05: (mnemo, operands) = ("ADD", $"AX,0x{Read16(code, ref pos):X4}"); break;
            // PUSH/POP ES
            case 0x06: (mnemo, operands) = ("PUSH", "ES"); break;
            case 0x07: (mnemo, operands) = ("POP",  "ES"); break;

            // OR
            case 0x08: (mnemo, operands) = AluRmR(code, ref pos, "OR", w: false, segOverride); break;
            case 0x09: (mnemo, operands) = AluRmR(code, ref pos, "OR", w: true,  segOverride); break;
            case 0x0A: (mnemo, operands) = AluRRm(code, ref pos, "OR", w: false, segOverride); break;
            case 0x0B: (mnemo, operands) = AluRRm(code, ref pos, "OR", w: true,  segOverride); break;
            case 0x0C: (mnemo, operands) = ("OR",  $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0x0D: (mnemo, operands) = ("OR",  $"AX,0x{Read16(code, ref pos):X4}"); break;
            case 0x0E: (mnemo, operands) = ("PUSH","CS"); break;

            // 0x0F – two-byte opcodes (80286+)
            case 0x0F: (mnemo, operands) = DecodeTwoByte(code, ref pos, segOverride); break;

            // ADC
            case 0x10: (mnemo, operands) = AluRmR(code, ref pos, "ADC", w: false, segOverride); break;
            case 0x11: (mnemo, operands) = AluRmR(code, ref pos, "ADC", w: true,  segOverride); break;
            case 0x12: (mnemo, operands) = AluRRm(code, ref pos, "ADC", w: false, segOverride); break;
            case 0x13: (mnemo, operands) = AluRRm(code, ref pos, "ADC", w: true,  segOverride); break;
            case 0x14: (mnemo, operands) = ("ADC", $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0x15: (mnemo, operands) = ("ADC", $"AX,0x{Read16(code, ref pos):X4}"); break;
            case 0x16: (mnemo, operands) = ("PUSH","SS"); break;
            case 0x17: (mnemo, operands) = ("POP", "SS"); break;

            // SBB
            case 0x18: (mnemo, operands) = AluRmR(code, ref pos, "SBB", w: false, segOverride); break;
            case 0x19: (mnemo, operands) = AluRmR(code, ref pos, "SBB", w: true,  segOverride); break;
            case 0x1A: (mnemo, operands) = AluRRm(code, ref pos, "SBB", w: false, segOverride); break;
            case 0x1B: (mnemo, operands) = AluRRm(code, ref pos, "SBB", w: true,  segOverride); break;
            case 0x1C: (mnemo, operands) = ("SBB", $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0x1D: (mnemo, operands) = ("SBB", $"AX,0x{Read16(code, ref pos):X4}"); break;
            case 0x1E: (mnemo, operands) = ("PUSH","DS"); break;
            case 0x1F: (mnemo, operands) = ("POP", "DS"); break;

            // AND
            case 0x20: (mnemo, operands) = AluRmR(code, ref pos, "AND", w: false, segOverride); break;
            case 0x21: (mnemo, operands) = AluRmR(code, ref pos, "AND", w: true,  segOverride); break;
            case 0x22: (mnemo, operands) = AluRRm(code, ref pos, "AND", w: false, segOverride); break;
            case 0x23: (mnemo, operands) = AluRRm(code, ref pos, "AND", w: true,  segOverride); break;
            case 0x24: (mnemo, operands) = ("AND", $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0x25: (mnemo, operands) = ("AND", $"AX,0x{Read16(code, ref pos):X4}"); break;
            // 0x26 is ES: prefix (handled above)
            case 0x27: (mnemo, operands) = ("DAA", ""); break;

            // SUB
            case 0x28: (mnemo, operands) = AluRmR(code, ref pos, "SUB", w: false, segOverride); break;
            case 0x29: (mnemo, operands) = AluRmR(code, ref pos, "SUB", w: true,  segOverride); break;
            case 0x2A: (mnemo, operands) = AluRRm(code, ref pos, "SUB", w: false, segOverride); break;
            case 0x2B: (mnemo, operands) = AluRRm(code, ref pos, "SUB", w: true,  segOverride); break;
            case 0x2C: (mnemo, operands) = ("SUB", $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0x2D: (mnemo, operands) = ("SUB", $"AX,0x{Read16(code, ref pos):X4}"); break;
            // 0x2E is CS: prefix
            case 0x2F: (mnemo, operands) = ("DAS", ""); break;

            // XOR
            case 0x30: (mnemo, operands) = AluRmR(code, ref pos, "XOR", w: false, segOverride); break;
            case 0x31: (mnemo, operands) = AluRmR(code, ref pos, "XOR", w: true,  segOverride); break;
            case 0x32: (mnemo, operands) = AluRRm(code, ref pos, "XOR", w: false, segOverride); break;
            case 0x33: (mnemo, operands) = AluRRm(code, ref pos, "XOR", w: true,  segOverride); break;
            case 0x34: (mnemo, operands) = ("XOR", $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0x35: (mnemo, operands) = ("XOR", $"AX,0x{Read16(code, ref pos):X4}"); break;
            // 0x36 is SS: prefix
            case 0x37: (mnemo, operands) = ("AAA", ""); break;

            // CMP
            case 0x38: (mnemo, operands) = AluRmR(code, ref pos, "CMP", w: false, segOverride); break;
            case 0x39: (mnemo, operands) = AluRmR(code, ref pos, "CMP", w: true,  segOverride); break;
            case 0x3A: (mnemo, operands) = AluRRm(code, ref pos, "CMP", w: false, segOverride); break;
            case 0x3B: (mnemo, operands) = AluRRm(code, ref pos, "CMP", w: true,  segOverride); break;
            case 0x3C: (mnemo, operands) = ("CMP", $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0x3D: (mnemo, operands) = ("CMP", $"AX,0x{Read16(code, ref pos):X4}"); break;
            // 0x3E is DS: prefix
            case 0x3F: (mnemo, operands) = ("AAS", ""); break;

            // INC reg16
            case 0x40: case 0x41: case 0x42: case 0x43:
            case 0x44: case 0x45: case 0x46: case 0x47:
                (mnemo, operands) = ("INC", Reg16[op & 7]); break;

            // DEC reg16
            case 0x48: case 0x49: case 0x4A: case 0x4B:
            case 0x4C: case 0x4D: case 0x4E: case 0x4F:
                (mnemo, operands) = ("DEC", Reg16[op & 7]); break;

            // PUSH reg16
            case 0x50: case 0x51: case 0x52: case 0x53:
            case 0x54: case 0x55: case 0x56: case 0x57:
                (mnemo, operands) = ("PUSH", Reg16[op & 7]); break;

            // POP reg16
            case 0x58: case 0x59: case 0x5A: case 0x5B:
            case 0x5C: case 0x5D: case 0x5E: case 0x5F:
                (mnemo, operands) = ("POP", Reg16[op & 7]); break;

            // PUSHA / POPA (80186+)
            case 0x60: (mnemo, operands) = ("PUSHA", ""); break;
            case 0x61: (mnemo, operands) = ("POPA",  ""); break;

            // BOUND (80186+)
            case 0x62:
            {
                var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                (mnemo, operands) = ("BOUND", $"{Reg16[reg]},{rmStr}");
                break;
            }

            // PUSH imm16 / PUSH imm8sx
            case 0x68: (mnemo, operands) = ("PUSH", $"0x{Read16(code, ref pos):X4}"); break;
            case 0x6A: (mnemo, operands) = ("PUSH", $"0x{(sbyte)Read8(code, ref pos):X2}"); break;

            // IMUL reg16, r/m16, imm
            case 0x69:
            {
                var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                ushort imm = Read16(code, ref pos);
                (mnemo, operands) = ("IMUL", $"{Reg16[reg]},{rmStr},0x{imm:X4}");
                break;
            }
            case 0x6B:
            {
                var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                sbyte imm = (sbyte)Read8(code, ref pos);
                (mnemo, operands) = ("IMUL", $"{Reg16[reg]},{rmStr},0x{imm:X2}");
                break;
            }

            // INS / OUTS (80186+)
            case 0x6C: (mnemo, operands) = (repPrefix ? "REP INSB"  : "INSB",  ""); break;
            case 0x6D: (mnemo, operands) = (repPrefix ? "REP INSW"  : "INSW",  ""); break;
            case 0x6E: (mnemo, operands) = (repPrefix ? "REP OUTSB" : "OUTSB", ""); break;
            case 0x6F: (mnemo, operands) = (repPrefix ? "REP OUTSW" : "OUTSW", ""); break;

            // Short conditional jumps (rel8)
            case 0x70: (mnemo, operands) = ShortJump(code, ref pos, start, "JO");   break;
            case 0x71: (mnemo, operands) = ShortJump(code, ref pos, start, "JNO");  break;
            case 0x72: (mnemo, operands) = ShortJump(code, ref pos, start, "JB");   break;
            case 0x73: (mnemo, operands) = ShortJump(code, ref pos, start, "JNB");  break;
            case 0x74: (mnemo, operands) = ShortJump(code, ref pos, start, "JZ");   break;
            case 0x75: (mnemo, operands) = ShortJump(code, ref pos, start, "JNZ");  break;
            case 0x76: (mnemo, operands) = ShortJump(code, ref pos, start, "JBE");  break;
            case 0x77: (mnemo, operands) = ShortJump(code, ref pos, start, "JA");   break;
            case 0x78: (mnemo, operands) = ShortJump(code, ref pos, start, "JS");   break;
            case 0x79: (mnemo, operands) = ShortJump(code, ref pos, start, "JNS");  break;
            case 0x7A: (mnemo, operands) = ShortJump(code, ref pos, start, "JP");   break;
            case 0x7B: (mnemo, operands) = ShortJump(code, ref pos, start, "JNP");  break;
            case 0x7C: (mnemo, operands) = ShortJump(code, ref pos, start, "JL");   break;
            case 0x7D: (mnemo, operands) = ShortJump(code, ref pos, start, "JGE");  break;
            case 0x7E: (mnemo, operands) = ShortJump(code, ref pos, start, "JLE");  break;
            case 0x7F: (mnemo, operands) = ShortJump(code, ref pos, start, "JG");   break;

            // Group 1: ALU r/m, imm
            case 0x80: (mnemo, operands) = Group1(code, ref pos, w: false, signExt: false, segOverride); break;
            case 0x81: (mnemo, operands) = Group1(code, ref pos, w: true,  signExt: false, segOverride); break;
            case 0x82: (mnemo, operands) = Group1(code, ref pos, w: false, signExt: true,  segOverride); break;
            case 0x83: (mnemo, operands) = Group1(code, ref pos, w: true,  signExt: true,  segOverride); break;

            // TEST r/m, r
            case 0x84: (mnemo, operands) = AluRmR(code, ref pos, "TEST", w: false, segOverride); break;
            case 0x85: (mnemo, operands) = AluRmR(code, ref pos, "TEST", w: true,  segOverride); break;

            // XCHG r/m, r
            case 0x86: (mnemo, operands) = AluRmR(code, ref pos, "XCHG", w: false, segOverride); break;
            case 0x87: (mnemo, operands) = AluRmR(code, ref pos, "XCHG", w: true,  segOverride); break;

            // MOV r/m, r  and  MOV r, r/m
            case 0x88: (mnemo, operands) = AluRmR(code, ref pos, "MOV", w: false, segOverride); break;
            case 0x89: (mnemo, operands) = AluRmR(code, ref pos, "MOV", w: true,  segOverride); break;
            case 0x8A: (mnemo, operands) = AluRRm(code, ref pos, "MOV", w: false, segOverride); break;
            case 0x8B: (mnemo, operands) = AluRRm(code, ref pos, "MOV", w: true,  segOverride); break;

            // MOV r/m16, Sreg
            case 0x8C:
            {
                var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                (mnemo, operands) = ("MOV", $"{rmStr},{RegSeg[reg & 3]}");
                break;
            }

            // LEA reg16, m
            case 0x8D:
            {
                var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                (mnemo, operands) = ("LEA", $"{Reg16[reg]},{rmStr}");
                break;
            }

            // MOV Sreg, r/m16
            case 0x8E:
            {
                var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                (mnemo, operands) = ("MOV", $"{RegSeg[reg & 3]},{rmStr}");
                break;
            }

            // POP r/m16
            case 0x8F:
            {
                var (rmStr, _, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                (mnemo, operands) = ("POP", rmStr);
                break;
            }

            // NOP / XCHG AX, reg
            case 0x90: (mnemo, operands) = ("NOP",  ""); break;
            case 0x91: case 0x92: case 0x93: case 0x94:
            case 0x95: case 0x96: case 0x97:
                (mnemo, operands) = ("XCHG", $"AX,{Reg16[op & 7]}"); break;

            // CBW / CWD
            case 0x98: (mnemo, operands) = ("CBW", ""); break;
            case 0x99: (mnemo, operands) = ("CWD", ""); break;

            // CALL far imm32
            case 0x9A:
            {
                ushort off = Read16(code, ref pos);
                ushort seg = Read16(code, ref pos);
                (mnemo, operands) = ("CALL FAR", $"0x{seg:X4}:0x{off:X4}");
                break;
            }

            // WAIT / FWAIT
            case 0x9B: (mnemo, operands) = ("WAIT", ""); break;

            // PUSHF / POPF
            case 0x9C: (mnemo, operands) = ("PUSHF", ""); break;
            case 0x9D: (mnemo, operands) = ("POPF",  ""); break;

            // SAHF / LAHF
            case 0x9E: (mnemo, operands) = ("SAHF", ""); break;
            case 0x9F: (mnemo, operands) = ("LAHF", ""); break;

            // MOV AL/AX, [imm]  and  MOV [imm], AL/AX
            case 0xA0:
            {
                ushort addr = Read16(code, ref pos);
                string mem = MemRef(segOverride, $"0x{addr:X4}", w: false);
                (mnemo, operands) = ("MOV", $"AL,{mem}");
                break;
            }
            case 0xA1:
            {
                ushort addr = Read16(code, ref pos);
                string mem = MemRef(segOverride, $"0x{addr:X4}", w: true);
                (mnemo, operands) = ("MOV", $"AX,{mem}");
                break;
            }
            case 0xA2:
            {
                ushort addr = Read16(code, ref pos);
                string mem = MemRef(segOverride, $"0x{addr:X4}", w: false);
                (mnemo, operands) = ("MOV", $"{mem},AL");
                break;
            }
            case 0xA3:
            {
                ushort addr = Read16(code, ref pos);
                string mem = MemRef(segOverride, $"0x{addr:X4}", w: true);
                (mnemo, operands) = ("MOV", $"{mem},AX");
                break;
            }

            // String operations
            case 0xA4: (mnemo, operands) = (repPrefix ? "REP MOVSB"  : "MOVSB",  ""); break;
            case 0xA5: (mnemo, operands) = (repPrefix ? "REP MOVSW"  : "MOVSW",  ""); break;
            case 0xA6: (mnemo, operands) = (repnePrefix ? "REPNE CMPSB" : repPrefix ? "REPE CMPSB" : "CMPSB", ""); break;
            case 0xA7: (mnemo, operands) = (repnePrefix ? "REPNE CMPSW" : repPrefix ? "REPE CMPSW" : "CMPSW", ""); break;

            // TEST AL/AX, imm
            case 0xA8: (mnemo, operands) = ("TEST", $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0xA9: (mnemo, operands) = ("TEST", $"AX,0x{Read16(code, ref pos):X4}"); break;

            // STOS / LODS / SCAS
            case 0xAA: (mnemo, operands) = (repPrefix ? "REP STOSB"  : "STOSB",  ""); break;
            case 0xAB: (mnemo, operands) = (repPrefix ? "REP STOSW"  : "STOSW",  ""); break;
            case 0xAC: (mnemo, operands) = (repPrefix ? "REP LODSB"  : "LODSB",  ""); break;
            case 0xAD: (mnemo, operands) = (repPrefix ? "REP LODSW"  : "LODSW",  ""); break;
            case 0xAE: (mnemo, operands) = (repnePrefix ? "REPNE SCASB" : repPrefix ? "REPE SCASB" : "SCASB", ""); break;
            case 0xAF: (mnemo, operands) = (repnePrefix ? "REPNE SCASW" : repPrefix ? "REPE SCASW" : "SCASW", ""); break;

            // MOV reg8, imm8
            case 0xB0: case 0xB1: case 0xB2: case 0xB3:
            case 0xB4: case 0xB5: case 0xB6: case 0xB7:
                (mnemo, operands) = ("MOV", $"{Reg8[op & 7]},0x{Read8(code, ref pos):X2}"); break;

            // MOV reg16, imm16
            case 0xB8: case 0xB9: case 0xBA: case 0xBB:
            case 0xBC: case 0xBD: case 0xBE: case 0xBF:
                (mnemo, operands) = ("MOV", $"{Reg16[op & 7]},0x{Read16(code, ref pos):X4}"); break;

            // ROL/ROR/RCL/RCR/SHL/SHR/SAR r/m, imm8  (80186+)
            case 0xC0: (mnemo, operands) = Group2Imm(code, ref pos, w: false, segOverride); break;
            case 0xC1: (mnemo, operands) = Group2Imm(code, ref pos, w: true,  segOverride); break;

            // RET near (with / without stack pop)
            case 0xC2: (mnemo, operands) = ("RET", $"0x{Read16(code, ref pos):X4}"); break;
            case 0xC3: (mnemo, operands) = ("RET", ""); break;

            // LES / LDS
            case 0xC4:
            {
                var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                (mnemo, operands) = ("LES", $"{Reg16[reg]},{rmStr}");
                break;
            }
            case 0xC5:
            {
                var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                (mnemo, operands) = ("LDS", $"{Reg16[reg]},{rmStr}");
                break;
            }

            // MOV r/m8, imm8  and  MOV r/m16, imm16
            case 0xC6:
            {
                var (rmStr, _, _) = DecodeModRm(code, ref pos, w: false, segOverride);
                byte imm = Read8(code, ref pos);
                (mnemo, operands) = ("MOV", $"{rmStr},0x{imm:X2}");
                break;
            }
            case 0xC7:
            {
                var (rmStr, _, _) = DecodeModRm(code, ref pos, w: true, segOverride);
                ushort imm = Read16(code, ref pos);
                (mnemo, operands) = ("MOV", $"{rmStr},0x{imm:X4}");
                break;
            }

            // ENTER / LEAVE (80186+)
            case 0xC8:
            {
                ushort allocSize = Read16(code, ref pos);
                byte nestLevel   = Read8(code, ref pos);
                (mnemo, operands) = ("ENTER", $"0x{allocSize:X4},0x{nestLevel:X2}");
                break;
            }
            case 0xC9: (mnemo, operands) = ("LEAVE", ""); break;

            // RET far
            case 0xCA: (mnemo, operands) = ("RETF", $"0x{Read16(code, ref pos):X4}"); break;
            case 0xCB: (mnemo, operands) = ("RETF", ""); break;

            // INT3 / INT / INTO / IRET
            case 0xCC: (mnemo, operands) = ("INT",  "3"); break;
            case 0xCD: (mnemo, operands) = ("INT",  $"0x{Read8(code, ref pos):X2}"); break;
            case 0xCE: (mnemo, operands) = ("INTO", ""); break;
            case 0xCF: (mnemo, operands) = ("IRET", ""); break;

            // Group 2: shift/rotate  r/m, 1  and  r/m, CL
            case 0xD0: (mnemo, operands) = Group2One(code, ref pos, w: false, segOverride); break;
            case 0xD1: (mnemo, operands) = Group2One(code, ref pos, w: true,  segOverride); break;
            case 0xD2: (mnemo, operands) = Group2Cl (code, ref pos, w: false, segOverride); break;
            case 0xD3: (mnemo, operands) = Group2Cl (code, ref pos, w: true,  segOverride); break;

            // AAM / AAD
            case 0xD4: Read8(code, ref pos); (mnemo, operands) = ("AAM", ""); break;
            case 0xD5: Read8(code, ref pos); (mnemo, operands) = ("AAD", ""); break;
            case 0xD7: (mnemo, operands) = ("XLAT", ""); break;

            // ESC (FPU) – just emit as DB
            case 0xD8: case 0xD9: case 0xDA: case 0xDB:
            case 0xDC: case 0xDD: case 0xDE: case 0xDF:
            {
                byte modRmByte = Peek(code, pos);
                pos++;
                (mnemo, operands) = ("ESC", $"0x{op:X2},0x{modRmByte:X2}");
                break;
            }

            // LOOPNE / LOOPE / LOOP / JCXZ
            case 0xE0: (mnemo, operands) = ShortJump(code, ref pos, start, "LOOPNE"); break;
            case 0xE1: (mnemo, operands) = ShortJump(code, ref pos, start, "LOOPE");  break;
            case 0xE2: (mnemo, operands) = ShortJump(code, ref pos, start, "LOOP");   break;
            case 0xE3: (mnemo, operands) = ShortJump(code, ref pos, start, "JCXZ");   break;

            // IN / OUT (fixed port)
            case 0xE4: (mnemo, operands) = ("IN",  $"AL,0x{Read8(code, ref pos):X2}"); break;
            case 0xE5: (mnemo, operands) = ("IN",  $"AX,0x{Read8(code, ref pos):X2}"); break;
            case 0xE6: (mnemo, operands) = ("OUT", $"0x{Read8(code, ref pos):X2},AL"); break;
            case 0xE7: (mnemo, operands) = ("OUT", $"0x{Read8(code, ref pos):X2},AX"); break;

            // CALL / JMP near (rel16)
            case 0xE8:
            {
                short rel = (short)Read16(code, ref pos);
                int target = (pos + rel) & 0xFFFF;
                (mnemo, operands) = ("CALL", $"0x{target:X4}");
                break;
            }
            case 0xE9:
            {
                short rel = (short)Read16(code, ref pos);
                int target = (pos + rel) & 0xFFFF;
                (mnemo, operands) = ("JMP",  $"0x{target:X4}");
                break;
            }

            // JMP far
            case 0xEA:
            {
                ushort off = Read16(code, ref pos);
                ushort seg = Read16(code, ref pos);
                (mnemo, operands) = ("JMP FAR", $"0x{seg:X4}:0x{off:X4}");
                break;
            }

            // JMP short (rel8)
            case 0xEB: (mnemo, operands) = ShortJump(code, ref pos, start, "JMP"); break;

            // IN / OUT (DX port)
            case 0xEC: (mnemo, operands) = ("IN",  "AL,DX"); break;
            case 0xED: (mnemo, operands) = ("IN",  "AX,DX"); break;
            case 0xEE: (mnemo, operands) = ("OUT", "DX,AL"); break;
            case 0xEF: (mnemo, operands) = ("OUT", "DX,AX"); break;

            // LOCK prefix already consumed – if we get here it was stray
            case 0xF0: (mnemo, operands) = ("LOCK", ""); break;

            // HLT / CMC
            case 0xF4: (mnemo, operands) = ("HLT", ""); break;
            case 0xF5: (mnemo, operands) = ("CMC", ""); break;

            // Group 3: TEST/NOT/NEG/MUL/IMUL/DIV/IDIV
            case 0xF6: (mnemo, operands) = Group3(code, ref pos, w: false, segOverride); break;
            case 0xF7: (mnemo, operands) = Group3(code, ref pos, w: true,  segOverride); break;

            // CLC / STC / CLI / STI / CLD / STD
            case 0xF8: (mnemo, operands) = ("CLC", ""); break;
            case 0xF9: (mnemo, operands) = ("STC", ""); break;
            case 0xFA: (mnemo, operands) = ("CLI", ""); break;
            case 0xFB: (mnemo, operands) = ("STI", ""); break;
            case 0xFC: (mnemo, operands) = ("CLD", ""); break;
            case 0xFD: (mnemo, operands) = ("STD", ""); break;

            // Group 4: INC/DEC r/m8
            case 0xFE: (mnemo, operands) = Group4(code, ref pos, segOverride); break;

            // Group 5: INC/DEC/CALL/CALLF/JMP/JMPF/PUSH r/m16
            case 0xFF: (mnemo, operands) = Group5(code, ref pos, start, segOverride); break;

            default:
                (mnemo, operands) = ("DB", $"0x{op:X2}");
                break;
        }

        // Attach any relevant prefix strings to the mnemonic when they were
        // not already incorporated into string ops above.
        if (lockPrefix && !mnemo.StartsWith("LOCK"))
            mnemo = "LOCK " + mnemo;

        byte[] raw = code[start..pos];
        return new Instruction
        {
            Offset   = address,
            Bytes    = raw,
            Mnemonic = mnemo,
            Operands = operands,
        };
    }

    // -----------------------------------------------------------------------
    // Two-byte opcodes (0x0F prefix, 80286+)
    // -----------------------------------------------------------------------

    private (string mnemo, string ops) DecodeTwoByte(byte[] code, ref int pos, string? seg)
    {
        byte op = Read8(code, ref pos);
        return op switch
        {
            0x00 => Group6(code, ref pos, seg),
            0x01 => Group7(code, ref pos, seg),
            0x02 => DecodeModRmInstruction(code, ref pos, "LAR",  w: true,  regFirst: true,  seg),
            0x03 => DecodeModRmInstruction(code, ref pos, "LSL",  w: true,  regFirst: true,  seg),
            _ => ($"DB 0x0F,0x{op:X2}", ""),
        };
    }

    private (string mnemo, string ops) Group6(byte[] code, ref int pos, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, seg);
        return reg switch
        {
            0 => ("SLDT", rmStr),
            1 => ("STR",  rmStr),
            2 => ("LLDT", rmStr),
            3 => ("LTR",  rmStr),
            4 => ("VERR", rmStr),
            5 => ("VERW", rmStr),
            _ => ($"DB 0x0F,0x00", ""),
        };
    }

    private (string mnemo, string ops) Group7(byte[] code, ref int pos, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, seg);
        return reg switch
        {
            0 => ("SGDT", rmStr),
            1 => ("SIDT", rmStr),
            2 => ("LGDT", rmStr),
            3 => ("LIDT", rmStr),
            4 => ("SMSW", rmStr),
            6 => ("LMSW", rmStr),
            _ => ($"DB 0x0F,0x01", ""),
        };
    }

    private (string mnemo, string ops) DecodeModRmInstruction(
        byte[] code, ref int pos, string mnemonic, bool w, bool regFirst, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w, seg);
        string[] regs = w ? Reg16 : Reg8;
        return regFirst
            ? (mnemonic, $"{regs[reg]},{rmStr}")
            : (mnemonic, $"{rmStr},{regs[reg]}");
    }

    // -----------------------------------------------------------------------
    // Group decoders
    // -----------------------------------------------------------------------

    private static readonly string[] AluOps = ["ADD","OR","ADC","SBB","AND","SUB","XOR","CMP"];
    private static readonly string[] ShiftOps = ["ROL","ROR","RCL","RCR","SHL","SHR","SHL","SAR"];

    private (string mnemo, string ops) Group1(byte[] code, ref int pos, bool w, bool signExt, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w, seg);
        string mnemo = AluOps[reg];
        string imm;
        if (!w)
            imm = $"0x{Read8(code, ref pos):X2}";
        else if (signExt)
            imm = $"0x{(sbyte)Read8(code, ref pos):X4}";
        else
            imm = $"0x{Read16(code, ref pos):X4}";
        return (mnemo, $"{rmStr},{imm}");
    }

    private (string mnemo, string ops) Group2One(byte[] code, ref int pos, bool w, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w, seg);
        return (ShiftOps[reg], $"{rmStr},1");
    }

    private (string mnemo, string ops) Group2Cl(byte[] code, ref int pos, bool w, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w, seg);
        return (ShiftOps[reg], $"{rmStr},CL");
    }

    private (string mnemo, string ops) Group2Imm(byte[] code, ref int pos, bool w, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w, seg);
        byte cnt = Read8(code, ref pos);
        return (ShiftOps[reg], $"{rmStr},0x{cnt:X2}");
    }

    private (string mnemo, string ops) Group3(byte[] code, ref int pos, bool w, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w, seg);
        switch (reg)
        {
            case 0:
            {
                string imm = w ? $"0x{Read16(code, ref pos):X4}" : $"0x{Read8(code, ref pos):X2}";
                return ("TEST", $"{rmStr},{imm}");
            }
            case 2: return ("NOT",  rmStr);
            case 3: return ("NEG",  rmStr);
            case 4: return ("MUL",  rmStr);
            case 5: return ("IMUL", rmStr);
            case 6: return ("DIV",  rmStr);
            case 7: return ("IDIV", rmStr);
            default: return ($"DB 0x{(w ? 0xF7 : 0xF6):X2}", "");
        }
    }

    private (string mnemo, string ops) Group4(byte[] code, ref int pos, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: false, seg);
        return reg switch
        {
            0 => ("INC", rmStr),
            1 => ("DEC", rmStr),
            _ => ("DB",  $"0xFE"),
        };
    }

    private (string mnemo, string ops) Group5(byte[] code, ref int pos, int instrBase, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w: true, seg);
        return reg switch
        {
            0 => ("INC",      rmStr),
            1 => ("DEC",      rmStr),
            2 => ("CALL",     rmStr),
            3 => ("CALL FAR", rmStr),
            4 => ("JMP",      rmStr),
            5 => ("JMP FAR",  rmStr),
            6 => ("PUSH",     rmStr),
            _ => ("DB",       "0xFF"),
        };
    }

    // -----------------------------------------------------------------------
    // Convenience wrappers for common encodings
    // -----------------------------------------------------------------------

    // r/m operand first, reg second  (e.g. MOV [mem], reg)
    private (string mnemo, string ops) AluRmR(byte[] code, ref int pos, string mnemonic, bool w, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w, seg);
        string[] regs = w ? Reg16 : Reg8;
        return (mnemonic, $"{rmStr},{regs[reg]}");
    }

    // reg operand first, r/m second  (e.g. MOV reg, [mem])
    private (string mnemo, string ops) AluRRm(byte[] code, ref int pos, string mnemonic, bool w, string? seg)
    {
        var (rmStr, reg, _) = DecodeModRm(code, ref pos, w, seg);
        string[] regs = w ? Reg16 : Reg8;
        return (mnemonic, $"{regs[reg]},{rmStr}");
    }

    private (string mnemo, string ops) ShortJump(byte[] code, ref int pos, int instrBase, string mnemonic)
    {
        sbyte rel = (sbyte)Read8(code, ref pos);
        int target = (pos + rel) & 0xFFFF;
        return (mnemonic, $"0x{target:X4}");
    }

    // -----------------------------------------------------------------------
    // ModRM decoder
    // Returns: (effective-address string, reg field 0..7, r/m field 0..7)
    // -----------------------------------------------------------------------

    private (string ea, int reg, int rm) DecodeModRm(
        byte[] code, ref int pos, bool w, string? segOverride)
    {
        byte modrm = Read8(code, ref pos);
        int mod = (modrm >> 6) & 3;
        int reg = (modrm >> 3) & 7;
        int rm  =  modrm       & 7;

        if (mod == 3)
        {
            // Register operand
            string regName = w ? Reg16[rm] : Reg8[rm];
            return (regName, reg, rm);
        }

        // Memory operand
        string baseStr = RmBase[rm];
        string dispStr;

        if (mod == 0 && rm == 6)
        {
            // Direct address [disp16]
            ushort disp = Read16(code, ref pos);
            dispStr = $"0x{disp:X4}";
            baseStr = dispStr;
            dispStr = "";
        }
        else if (mod == 1)
        {
            sbyte disp8 = (sbyte)Read8(code, ref pos);
            if (disp8 < 0)
                dispStr = $"-0x{(byte)(-disp8):X2}";
            else if (disp8 > 0)
                dispStr = $"+0x{disp8:X2}";
            else
                dispStr = "";
        }
        else if (mod == 2)
        {
            short disp16 = (short)Read16(code, ref pos);
            if (disp16 < 0)
                dispStr = $"-0x{(ushort)(-disp16):X4}";
            else if (disp16 > 0)
                dispStr = $"+0x{disp16:X4}";
            else
                dispStr = "";
        }
        else
        {
            dispStr = "";
        }

        string addrStr = string.IsNullOrEmpty(dispStr) ? baseStr : baseStr + dispStr;
        string sizeHint = w ? "WORD PTR " : "BYTE PTR ";
        string segStr   = segOverride is not null ? segOverride + ":" : "";
        return ($"{sizeHint}{segStr}[{addrStr}]", reg, rm);
    }

    // -----------------------------------------------------------------------
    // Low-level read helpers
    // -----------------------------------------------------------------------

    private static byte Peek(byte[] code, int pos) => code[pos];

    private static byte Read8(byte[] code, ref int pos) => code[pos++];

    private static ushort Read16(byte[] code, ref int pos)
    {
        ushort val = (ushort)(code[pos] | (code[pos + 1] << 8));
        pos += 2;
        return val;
    }

    private static string MemRef(string? segOverride, string addr, bool w)
    {
        string seg  = segOverride is not null ? segOverride + ":" : "";
        string size = w ? "WORD PTR " : "BYTE PTR ";
        return $"{size}{seg}[{addr}]";
    }
}
