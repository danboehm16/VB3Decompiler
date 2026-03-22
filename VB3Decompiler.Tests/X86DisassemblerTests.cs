using VB3Decompiler.Disassembly;

namespace VB3Decompiler.Tests;

public class X86DisassemblerTests
{
    private readonly X86Disassembler _asm = new();

    // Helper: disassemble a single instruction and return it.
    private Instruction Single(params byte[] code)
    {
        var result = _asm.Disassemble(code);
        Assert.NotEmpty(result);
        return result[0];
    }

    // -----------------------------------------------------------------------
    // NOP / single-byte ops
    // -----------------------------------------------------------------------

    [Fact]
    public void Nop_IsDecoded()
    {
        var instr = Single(0x90);
        Assert.Equal("NOP", instr.Mnemonic);
        Assert.Equal("", instr.Operands);
    }

    [Fact]
    public void Hlt_IsDecoded()
    {
        var instr = Single(0xF4);
        Assert.Equal("HLT", instr.Mnemonic);
    }

    [Fact]
    public void Ret_Near_IsDecoded()
    {
        var instr = Single(0xC3);
        Assert.Equal("RET", instr.Mnemonic);
        Assert.Equal("", instr.Operands);
    }

    [Fact]
    public void Retf_IsDecoded()
    {
        var instr = Single(0xCB);
        Assert.Equal("RETF", instr.Mnemonic);
    }

    // -----------------------------------------------------------------------
    // MOV family
    // -----------------------------------------------------------------------

    [Fact]
    public void Mov_Reg8_Imm8_IsDecoded()
    {
        // MOV AL, 0x42
        var instr = Single(0xB0, 0x42);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Equal("AL,0x42", instr.Operands);
    }

    [Fact]
    public void Mov_Reg16_Imm16_IsDecoded()
    {
        // MOV AX, 0x1234
        var instr = Single(0xB8, 0x34, 0x12);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Equal("AX,0x1234", instr.Operands);
    }

    [Fact]
    public void Mov_Reg16_Imm16_Bx_IsDecoded()
    {
        // MOV BX, 0x0005
        var instr = Single(0xBB, 0x05, 0x00);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Equal("BX,0x0005", instr.Operands);
    }

    [Fact]
    public void Mov_RM_Reg_IsDecoded()
    {
        // MOV [BX+SI], AX   (0x89, ModRM=0x00: mod=00, reg=0(AX), rm=0(BX+SI))
        var instr = Single(0x89, 0x00);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Contains("AX", instr.Operands);
    }

    [Fact]
    public void Mov_Reg_RM_IsDecoded()
    {
        // MOV AX, [BX+SI]   (0x8B, ModRM=0x00)
        var instr = Single(0x8B, 0x00);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Contains("AX", instr.Operands);
    }

    [Fact]
    public void Mov_Reg_DirectMem_IsDecoded()
    {
        // MOV AX, [0x1234]  (0x8B, ModRM: mod=00, reg=0, rm=6 => direct) + disp16
        var instr = Single(0x8B, 0x06, 0x34, 0x12);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Contains("AX", instr.Operands);
        Assert.Contains("0x1234", instr.Operands);
    }

    [Fact]
    public void Mov_MemImm16_IsDecoded()
    {
        // MOV WORD PTR [BX+SI], 0xABCD  (0xC7, ModRM=0x00, imm16)
        var instr = Single(0xC7, 0x00, 0xCD, 0xAB);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Contains("0xABCD", instr.Operands);
    }

    // -----------------------------------------------------------------------
    // PUSH / POP
    // -----------------------------------------------------------------------

    [Fact]
    public void Push_Reg16_IsDecoded()
    {
        // PUSH BX (0x53)
        var instr = Single(0x53);
        Assert.Equal("PUSH", instr.Mnemonic);
        Assert.Equal("BX", instr.Operands);
    }

    [Fact]
    public void Pop_Reg16_IsDecoded()
    {
        // POP SI (0x5E)
        var instr = Single(0x5E);
        Assert.Equal("POP", instr.Mnemonic);
        Assert.Equal("SI", instr.Operands);
    }

    [Fact]
    public void Push_Imm16_IsDecoded()
    {
        // PUSH 0x0064 (0x68, 0x64, 0x00)
        var instr = Single(0x68, 0x64, 0x00);
        Assert.Equal("PUSH", instr.Mnemonic);
        Assert.Contains("0x0064", instr.Operands);
    }

    [Fact]
    public void Push_Es_IsDecoded()
    {
        var instr = Single(0x06);
        Assert.Equal("PUSH", instr.Mnemonic);
        Assert.Equal("ES", instr.Operands);
    }

    // -----------------------------------------------------------------------
    // ALU ops
    // -----------------------------------------------------------------------

    [Fact]
    public void Add_Al_Imm8_IsDecoded()
    {
        var instr = Single(0x04, 0x10);
        Assert.Equal("ADD", instr.Mnemonic);
        Assert.Equal("AL,0x10", instr.Operands);
    }

    [Fact]
    public void Add_Ax_Imm16_IsDecoded()
    {
        var instr = Single(0x05, 0xFF, 0x00);
        Assert.Equal("ADD", instr.Mnemonic);
        Assert.Equal("AX,0x00FF", instr.Operands);
    }

    [Fact]
    public void Sub_Rm_Imm8_IsDecoded()
    {
        // SUB AX, 1  (0x83, ModRM=0xE8: mod=11, reg=5(SUB), rm=0(AX)) imm8
        var instr = Single(0x83, 0xE8, 0x01);
        Assert.Equal("SUB", instr.Mnemonic);
        Assert.Contains("AX", instr.Operands);
        Assert.Contains("0x0001", instr.Operands);
    }

    [Fact]
    public void Cmp_Ax_Imm16_IsDecoded()
    {
        var instr = Single(0x3D, 0x00, 0x00);
        Assert.Equal("CMP", instr.Mnemonic);
        Assert.Equal("AX,0x0000", instr.Operands);
    }

    [Fact]
    public void Xor_Reg_Reg_IsDecoded()
    {
        // XOR AX, AX  (0x33, ModRM=0xC0: mod=11, reg=0(AX), rm=0(AX))
        var instr = Single(0x33, 0xC0);
        Assert.Equal("XOR", instr.Mnemonic);
        Assert.Equal("AX,AX", instr.Operands);
    }

    [Fact]
    public void And_Reg_Rm_IsDecoded()
    {
        // AND CX, BX  (0x23, ModRM=0xCB: mod=11, reg=1(CX), rm=3(BX))
        var instr = Single(0x23, 0xCB);
        Assert.Equal("AND", instr.Mnemonic);
        Assert.Equal("CX,BX", instr.Operands);
    }

    [Fact]
    public void Or_Al_Imm8_IsDecoded()
    {
        var instr = Single(0x0C, 0x80);
        Assert.Equal("OR", instr.Mnemonic);
        Assert.Equal("AL,0x80", instr.Operands);
    }

    // -----------------------------------------------------------------------
    // INC / DEC
    // -----------------------------------------------------------------------

    [Fact]
    public void Inc_Reg16_IsDecoded()
    {
        // INC CX (0x41)
        var instr = Single(0x41);
        Assert.Equal("INC", instr.Mnemonic);
        Assert.Equal("CX", instr.Operands);
    }

    [Fact]
    public void Dec_Reg16_IsDecoded()
    {
        // DEC BX (0x4B)
        var instr = Single(0x4B);
        Assert.Equal("DEC", instr.Mnemonic);
        Assert.Equal("BX", instr.Operands);
    }

    // -----------------------------------------------------------------------
    // Jump / call
    // -----------------------------------------------------------------------

    [Fact]
    public void Jmp_Short_IsDecoded()
    {
        // JMP +2 (0xEB, 0x00 → target = pos after instr = 2)
        var instr = Single(0xEB, 0x00);
        Assert.Equal("JMP", instr.Mnemonic);
        Assert.Equal("0x0002", instr.Operands);
    }

    [Fact]
    public void Jz_Short_IsDecoded()
    {
        // JZ +2 (0x74, 0x00)
        var instr = Single(0x74, 0x00);
        Assert.Equal("JZ", instr.Mnemonic);
    }

    [Fact]
    public void Jnz_Short_IsDecoded()
    {
        var instr = Single(0x75, 0x00);
        Assert.Equal("JNZ", instr.Mnemonic);
    }

    [Fact]
    public void Call_Near_IsDecoded()
    {
        // CALL +0  (0xE8, 0x00, 0x00 → calls pos 3)
        var instr = Single(0xE8, 0x00, 0x00);
        Assert.Equal("CALL", instr.Mnemonic);
        Assert.Equal("0x0003", instr.Operands);
    }

    [Fact]
    public void Jmp_Near_IsDecoded()
    {
        // JMP  0x0010 (0xE9, 0x0D, 0x00 → 3 + 13 = 16)
        var instr = Single(0xE9, 0x0D, 0x00);
        Assert.Equal("JMP", instr.Mnemonic);
        Assert.Equal("0x0010", instr.Operands);
    }

    // -----------------------------------------------------------------------
    // Shift / rotate
    // -----------------------------------------------------------------------

    [Fact]
    public void Shl_Reg_1_IsDecoded()
    {
        // SHL AX, 1  (0xD1, ModRM=0xE0: mod=11, reg=4(SHL), rm=0(AX))
        var instr = Single(0xD1, 0xE0);
        Assert.Equal("SHL", instr.Mnemonic);
        Assert.Equal("AX,1", instr.Operands);
    }

    [Fact]
    public void Shr_Reg_Cl_IsDecoded()
    {
        // SHR BX, CL  (0xD3, ModRM=0xEB: mod=11, reg=5(SHR), rm=3(BX))
        var instr = Single(0xD3, 0xEB);
        Assert.Equal("SHR", instr.Mnemonic);
        Assert.Equal("BX,CL", instr.Operands);
    }

    // -----------------------------------------------------------------------
    // String operations
    // -----------------------------------------------------------------------

    [Fact]
    public void Movsb_IsDecoded()
    {
        var instr = Single(0xA4);
        Assert.Equal("MOVSB", instr.Mnemonic);
    }

    [Fact]
    public void Rep_Movsw_IsDecoded()
    {
        var result = _asm.Disassemble([0xF3, 0xA5]);
        Assert.Single(result);
        Assert.Contains("MOVSW", result[0].Mnemonic);
    }

    [Fact]
    public void Stosb_IsDecoded()
    {
        var instr = Single(0xAA);
        Assert.Equal("STOSB", instr.Mnemonic);
    }

    // -----------------------------------------------------------------------
    // Misc
    // -----------------------------------------------------------------------

    [Fact]
    public void Int_IsDecoded()
    {
        var instr = Single(0xCD, 0x21);
        Assert.Equal("INT", instr.Mnemonic);
        Assert.Equal("0x21", instr.Operands);
    }

    [Fact]
    public void Int3_IsDecoded()
    {
        var instr = Single(0xCC);
        Assert.Equal("INT", instr.Mnemonic);
        Assert.Equal("3", instr.Operands);
    }

    [Fact]
    public void Lea_IsDecoded()
    {
        // LEA AX, [BX+0x04]  (0x8D, ModRM=0x47: mod=01, reg=0(AX), rm=7(BX)), disp8=4
        var instr = Single(0x8D, 0x47, 0x04);
        Assert.Equal("LEA", instr.Mnemonic);
        Assert.Contains("AX", instr.Operands);
        Assert.Contains("BX", instr.Operands);
    }

    [Fact]
    public void Xchg_Ax_Reg_IsDecoded()
    {
        // XCHG AX, BX  (0x93)
        var instr = Single(0x93);
        Assert.Equal("XCHG", instr.Mnemonic);
        Assert.Equal("AX,BX", instr.Operands);
    }

    [Fact]
    public void Cbw_IsDecoded()
    {
        var instr = Single(0x98);
        Assert.Equal("CBW", instr.Mnemonic);
    }

    [Fact]
    public void Mul_Rm_IsDecoded()
    {
        // MUL BX  (0xF7, ModRM=0xE3: mod=11, reg=4(MUL), rm=3(BX))
        var instr = Single(0xF7, 0xE3);
        Assert.Equal("MUL", instr.Mnemonic);
        Assert.Equal("BX", instr.Operands);
    }

    [Fact]
    public void Div_Rm_IsDecoded()
    {
        // DIV CX  (0xF7, ModRM=0xF1: mod=11, reg=6(DIV), rm=1(CX))
        var instr = Single(0xF7, 0xF1);
        Assert.Equal("DIV", instr.Mnemonic);
        Assert.Equal("CX", instr.Operands);
    }

    [Fact]
    public void Neg_Rm_IsDecoded()
    {
        // NEG AX  (0xF7, ModRM=0xD8: mod=11, reg=3(NEG), rm=0(AX))
        var instr = Single(0xF7, 0xD8);
        Assert.Equal("NEG", instr.Mnemonic);
        Assert.Equal("AX", instr.Operands);
    }

    [Fact]
    public void Call_Far_Imm_IsDecoded()
    {
        // CALL FAR 0x1234:0x5678
        var instr = Single(0x9A, 0x78, 0x56, 0x34, 0x12);
        Assert.Equal("CALL FAR", instr.Mnemonic);
        Assert.Contains("0x1234", instr.Operands);
        Assert.Contains("0x5678", instr.Operands);
    }

    [Fact]
    public void Push_Ds_IsDecoded()
    {
        var instr = Single(0x1E);
        Assert.Equal("PUSH", instr.Mnemonic);
        Assert.Equal("DS", instr.Operands);
    }

    [Fact]
    public void Pop_Ds_IsDecoded()
    {
        var instr = Single(0x1F);
        Assert.Equal("POP", instr.Mnemonic);
        Assert.Equal("DS", instr.Operands);
    }

    [Fact]
    public void Clc_IsDecoded()
    {
        var instr = Single(0xF8);
        Assert.Equal("CLC", instr.Mnemonic);
    }

    [Fact]
    public void Cld_IsDecoded()
    {
        var instr = Single(0xFC);
        Assert.Equal("CLD", instr.Mnemonic);
    }

    [Fact]
    public void Std_IsDecoded()
    {
        var instr = Single(0xFD);
        Assert.Equal("STD", instr.Mnemonic);
    }

    // -----------------------------------------------------------------------
    // Multi-instruction stream
    // -----------------------------------------------------------------------

    [Fact]
    public void MultipleInstructions_AreAllDecoded()
    {
        // PUSH BP / MOV BP, SP / POP BP / RET  (4 instructions, 5 bytes)
        byte[] code = [0x55, 0x8B, 0xEC, 0x5D, 0xC3];
        var result = _asm.Disassemble(code);
        Assert.Equal(4, result.Count);
        Assert.Equal("PUSH", result[0].Mnemonic);
        Assert.Equal("BP",   result[0].Operands);
        Assert.Equal("MOV",  result[1].Mnemonic);
        Assert.Equal("RET",  result[3].Mnemonic);
    }

    [Fact]
    public void Instruction_ToString_ContainsOffset_And_Hex()
    {
        var instr = Single(0x90);
        string s = instr.ToString();
        Assert.Contains("0000", s);  // offset
        Assert.Contains("90",   s);  // hex byte
        Assert.Contains("NOP",  s);  // mnemonic
    }

    [Fact]
    public void Instruction_Offset_MatchesStartOffset()
    {
        var result = _asm.Disassemble([0x90, 0x90], startOffset: 0x100);
        Assert.Equal(0x100, result[0].Offset);
        Assert.Equal(0x101, result[1].Offset);
    }

    [Fact]
    public void SegmentOverride_IsIncluded_InOperand()
    {
        // ES: MOV AX, [BX+SI]  → 0x26, 0x8B, 0x00
        var instr = Single(0x26, 0x8B, 0x00);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Contains("ES:", instr.Operands);
    }

    [Fact]
    public void ModRM_Disp8_IsDecoded()
    {
        // MOV AX, [BX+0x10]  (0x8B, ModRM=0x47: mod=01, reg=0, rm=7) disp8=0x10
        var instr = Single(0x8B, 0x47, 0x10);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Contains("+0x10", instr.Operands);
        Assert.Contains("BX", instr.Operands);
    }

    [Fact]
    public void ModRM_Disp16_IsDecoded()
    {
        // MOV AX, [BX+0x1234]  (0x8B, ModRM=0x87: mod=10, reg=0, rm=7) disp16
        var instr = Single(0x8B, 0x87, 0x34, 0x12);
        Assert.Equal("MOV", instr.Mnemonic);
        Assert.Contains("0x1234", instr.Operands);
        Assert.Contains("BX", instr.Operands);
    }
}
