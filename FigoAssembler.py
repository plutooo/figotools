# Marvell FIGO assembler
# Flow Instructions Get Optimized!
# plutoo, souffle2, 2020
import sys
import struct

INSTRUCTION_PROTOTYPES = [
    [ "A64CMD"  , "C,rS,xT,K"   , "1111CCCCSSSSCCCCTTKKKKKK" ],
    [ "SEL.x"   , "rD,C,K,rT"   , "1110KKKKKKKKCCCCTTTTDDDD" ],
    [ "ADD.i"   , "rD,N,rT"     , "1101NNNNNNNNNNNNTTTTDDDD" ],
    [ "SUB.i"   , "rD,N,rT"     , "1100NNNNNNNNNNNNTTTTDDDD" ],
    [ "LD"      , "rD,N"        , "1011NNNNNNNNNNNNNNNNDDDD" ],
    [ "RD.i"    , "C,rD"        , "1010CCCCCCCCCCCCCCCCDDDD" ],
    [ "WR.i"    , "C,rT"        , "1001CCCCCCCCCCCCTTTTCCCC" ],
    [ "PREJ"    , "C,B,A"       , "1000AAAAAAAACCCCBBBBBBBB" ],
    [ "X.RD.i"  , "C,xT"        , "0111CCCCCCCCCCCCTT-0CCCC" ],
    [ "X.WR.i"  , "C,xT"        , "0111CCCCCCCCCCCCTT-1CCCC" ],
    [ "RD.INC"  , "rS,N,rD"     , "0110NNNNSSSSNNNN--00DDDD" ],
    [ "OFF.RD"  , "N,rD"        , "0110NNNN----NNNN--01DDDD" ],
    [ "X.A64LD" , "N,xT,rS"     , "0110NNNNSSSSNNNNTT10----" ],
    [ "A64LD"   , "C,rD,rS"     , "0110NNNNSSSSNNNN--11DDDD" ],
    [ "WR"      , "rS,N,rT"     , "0101NNNNSSSSNNNNTTTT0000" ],
    [ "WR.INC"  , "rS,N,rT"     , "0101NNNNSSSSNNNNTTTT0001" ],
    [ "INC.WR"  , "rS,N,rT"     , "0101NNNNSSSSNNNNTTTT0010" ],
    [ "CMP.i"   , "N,rT"        , "0101NNNNNNNNNNNNTTTT0100" ],
    [ "X.RD.INC", "rS,N,xT"     , "0101NNNNSSSSNNNNTT--1000" ],
    [ "X.OFF.RD", "N,xT"        , "0101NNNN----NNNNTT--1001" ],
    [ "X.WR"    , "rS,N,xT"     , "0101NNNNSSSSNNNNTT--1100" ],
    [ "X.WR.INC", "rS,N,xT"     , "0101NNNNSSSSNNNNTT--1101" ],
    [ "X.INC.WR", "rS,N,xT"     , "0101NNNNSSSSNNNNTT--1110" ],
    [ "Q.RD.INC", "rS,N,qT"     , "0100NNNNSSSSNNNN00TTTTTT" ],
    [ "Q.OFF.RD", "N,qT"        , "0100NNNN----NNNN01TTTTTT" ],
    [ "Q.WR"    , "rS,N,qT"     , "0100NNNNSSSSNNNN10TTTTTT" ],
    [ "Q.WR.INC", "rS,N,qT"     , "0100NNNNSSSSNNNN11TTTTTT" ],
    [ "Q.A64LD" , "C,qS"        , "00110001CCCCCCCC--SSSSSS" ],
    [ "X2Q"     , "qS,xT"       , "00110010--------TTSSSSSS" ],
    [ "Q2X"     , "xT,qS"       , "00110011--------TTSSSSSS" ],
    [ "PREJR"   , "C,B,rS"      , "00110100SSSSCCCCBBBBBBBB" ],
    [ "ORL"     , "rD,rS,C"     , "00101000SSSSCCCCCCCCDDDD" ],
    [ "ORH"     , "rD,rS,C"     , "00101001SSSSCCCCCCCCDDDD" ],
    [ "ANDL"    , "rD,rS,C"     , "00101010SSSSCCCCCCCCDDDD" ],
    [ "ANDH"    , "rD,rS,C"     , "00101011SSSSCCCCCCCCDDDD" ],
    [ "XORL"    , "rD,rS,C"     , "00101100SSSSCCCCCCCCDDDD" ],
    [ "XORH"    , "rD,rS,C"     , "00101101SSSSCCCCCCCCDDDD" ],
    [ "MUL.i"   , "rS,C"        , "00101110SSSSCCCCCCCC----" ],
    [ "DIV.i"   , "rS,C"        , "00101111SSSSCCCCCCCC----" ],
    [ "ADD"     , "rD,rS,rT"    , "00010000SSSS----TTTTDDDD" ],
    [ "ADDC"    , "rD,rS,rT"    , "00010001SSSS----TTTTDDDD" ],
    [ "SUB"     , "rD,rS,rT"    , "00010010SSSS----TTTTDDDD" ],
    [ "SUBC"    , "rD,rS,rT"    , "00010011SSSS----TTTTDDDD" ],
    [ "OR"      , "rD,rS,rT"    , "00010100SSSS----TTTTDDDD" ],
    [ "AND"     , "rD,rS,rT"    , "00010101SSSS----TTTTDDDD" ],
    [ "XOR"     , "rD,rS,rT"    , "00010110SSSS----TTTTDDDD" ],
    [ "ASR.i"   , "rD,rS,C"     , "00011010SSSS----CCCCDDDD" ],
    [ "ASR"     , "rD,rS,rT"    , "00011011SSSS----TTTTDDDD" ],
    [ "SL.i"    , "rD,rS,C"     , "00011100SSSS----CCCCDDDD" ],
    [ "SL"      , "rD,rS,rT"    , "00011101SSSS----TTTTDDDD" ],
    [ "SR.i"    , "rD,rS,C"     , "00011110SSSS----CCCCDDDD" ],
    [ "SR"      , "rD,rS,rT"    , "00011111SSSS----TTTTDDDD" ],
    [ "NOP"     , ""            , "000000000000000000000000" ],
    [ "CMP"     , "rS,rT"       , "00000001SSSS----TTTT----" ],
    [ "MUL"     , "rS,rT"       , "00000010SSSS----TTTT----" ],
    [ "DIV"     , "rS,rT"       , "00000011SSSS----TTTT----" ],
    [ "SEL"     , "rD,C,rS,rT"  , "00000100SSSSCCCCTTTTDDDD" ],
    [ "SEL.i"   , "rD,C,N,M"    , "00000101NNNNCCCCMMMMDDDD" ],
    [ "BFGET.i" , "rD,rS,C,K"   , "00000110SSSSCCCCKKKKDDDD" ],
    [ "BFSET.i" , "rS,rT,C,K"   , "00000111SSSSCCCCTTTTKKKK" ],
    [ "ST.FLG"  , "rT"          , "00001001--------TTTT----" ],
    [ "SYSCALL" , "C"           , "0000101CCCCCCCCCCCCCCCCC" ],
    [ "LD.FLG"  , "rD"          , "00001101------------DDDD" ],
    [ "LD.MDL"  , "rD"          , "00001110------------DDDD" ],
    [ "LD.MDH"  , "rD"          , "00001111------------DDDD" ],
]

# Little endian.
# These are 16-bit registers.
REGISTERS = [
    'sp',
    'tp',
    'a0',
    'a1',
    'a2',
    'a3',
    'a4',
    'a5',
    'a6',
    'a7',
    'a8',
    'a9',
    'a10',
    'a11',
    'a12',
    'a13',
]

# These are 64-bit registers.
REGISTERS_X = [
    'xsp',  # sp:tp:a0:a1
    'x2',   # a2:a3:a4:a5
    'x6',   # a6:a7:a8:a9
    'x10',  # a10:a11:a12:a13
]

CONDITIONS = {
    0b0000: 'Z',
    0b0001: 'C',
    0b0010: 'N',
    0b0011: 'V',
    0b0100: '!Z',
    0b0101: '!C',
    0b0110: 'NV', # Never
    0b0111: 'AL', # Always
    0b1000: 'G',
    0b1001: 'GS',
    0b1010: 'L',
    0b1011: 'LS',
    0b1100: '!G',
    0b1101: '!GS',
    0b1110: '!L',
    0b1111: '!LS',
}

def find_proto(mnemonic):
    for p in INSTRUCTION_PROTOTYPES:
        if p[0].lower().replace('.', '_') == mnemonic.lower():
            return p
    return None

class OperandBase:
    pass

class RegR(OperandBase):
    def __init__(self, value):
        self.value = value
    def get_int(self):
        return self.value

class RegX(OperandBase):
    def __init__(self, value):
        self.value = value
    def get_int(self):
        return self.value

class Cond(OperandBase):
    def __init__(self, value):
        self.value = value
    def get_int(self):
        return self.value

class Imm(OperandBase):
    pass

sp = RegR(0)
tp = RegR(1)
a0 = RegR(2)
a1 = RegR(3)
a2 = RegR(4)
a3 = RegR(5)
a4 = RegR(6)
a5 = RegR(7)
a6 = RegR(8)
a7 = RegR(9)
a8 = RegR(10)
a9 = RegR(11)
a10 = RegR(12)
a11 = RegR(13)
a12 = RegR(14)
a13 = RegR(15)

xsp = RegX(0)
x2  = RegX(1)
x6  = RegX(2)
x10 = RegX(3)

Z   = Cond(0)
C   = Cond(1)
N   = Cond(2)
V   = Cond(3)
NZ  = Cond(4)
NC  = Cond(5)
NV  = Cond(6)
AL  = Cond(7)
G   = Cond(8)
GS  = Cond(9)
L   = Cond(10)
LS  = Cond(11)
NG  = Cond(12)
NGS = Cond(13)
NL  = Cond(14)
NLS = Cond(15)

CONDITIONS = {
    0b0000: 'Z',
    0b0001: 'C',
    0b0010: 'N',
    0b0011: 'V',
    0b0100: '!Z',
    0b0101: '!C',
    0b0110: 'NV', # Never
    0b0111: 'AL', # Always
    0b1000: 'G',
    0b1001: 'GS',
    0b1010: 'L',
    0b1011: 'LS',
    0b1100: '!G',
    0b1101: '!GS',
    0b1110: '!L',
    0b1111: '!LS',
}

# Tests
assert a0.get_int() == 2

class InsnBase:
    def __init__(self, *operands):
        self.operands = list(operands)

    @staticmethod
    def get_mask_and_value(prototype):
        mask = ''
        value = ''
        for bit in prototype[2]:
            if bit == '0':
                value += '0'
                mask  += '1'
            elif bit == '1':
                value += '1'
                mask  += '1'
            else:
                value += '0'
                mask  += '0'
        return (int(mask, 2), int(value, 2))

    @staticmethod
    def get_sparse_extraction_map(prototype, letter):
        bit_positions = []
        for n, bit in enumerate(prototype[2]):
            if bit == letter:
                bit_positions += [ 23 - n ]
        return list(reversed(bit_positions))

    @staticmethod
    def insert_bitfield(sparse_map, value):
        field = 0
        for i, bit_pos in enumerate(sparse_map):
            field |= ((value >> i) & 1) << bit_pos
        return field

    def get_mnemonic(self):
        return self.__class__.__name__

    def encode(self):
        proto = find_proto(self.get_mnemonic())
        if not proto:
            raise Exception(self.get_mnemonic() + ' not found!')
        _, opcode = self.get_mask_and_value(proto)
        operand_pos = 0
        proto_operands = proto[1].split(',')
        if proto_operands == [""]:
            proto_operands = []
        for op_proto in proto_operands:
            if operand_pos >= len(self.operands):
                raise Exception(self.get_mnemonic() + ' has too few operands!')
            operand = self.operands[operand_pos]
            if op_proto.startswith('r'):
                sparse_map = self.get_sparse_extraction_map(proto, op_proto[1])
                if not isinstance(operand, RegR):
                    raise Exception(self.get_mnemonic() + ' expected RegR as operand %d!' % operand_pos)
                opcode |= self.insert_bitfield(sparse_map, operand.get_int())
            elif op_proto.startswith('x'):
                sparse_map = self.get_sparse_extraction_map(proto, op_proto[1])
                if not isinstance(operand, RegX):
                    raise Exception(self.get_mnemonic() + ' expected RegX as operand %d!' % operand_pos)
                opcode |= self.insert_bitfield(sparse_map, operand.get_int())
            else:
                sparse_map = self.get_sparse_extraction_map(proto, op_proto[0])
                imm = None
                if isinstance(operand, Imm):
                    imm = operand.get_int()
                elif type(operand) == int:
                    imm = operand
                elif isinstance(operand, Cond) and op_proto == 'C':
                    imm = operand.get_int()
                else:
                    raise Exception(self.get_mnemonic() + ' expected Imm as operand %d!' % operand_pos)
                opcode |= self.insert_bitfield(sparse_map, imm)
            operand_pos += 1
        if operand_pos != len(self.operands):
            raise Exception(self.get_mnemonic() + ' has too many operands!')
        return opcode

class A64CMD(InsnBase):
    pass
class SEL_x(InsnBase):
    pass
class ADD_i(InsnBase):
    pass
class SUB_i(InsnBase):
    pass
class LD(InsnBase):
    pass
class RD_i(InsnBase):
    pass
class WR_i(InsnBase):
    pass
class PREJ(InsnBase):
    pass
class X_RD_i(InsnBase):
    pass
class X_WR_i(InsnBase):
    pass
class RD_INC(InsnBase):
    pass
class OFF_RD(InsnBase):
    pass
class X_A64LD(InsnBase):
    pass
class A64LD(InsnBase):
    pass
class WR(InsnBase):
    pass
class WR_INC(InsnBase):
    pass
class INC_WR(InsnBase):
    pass
class CMP_i(InsnBase):
    pass
class X_RD_INC(InsnBase):
    pass
class X_OFF_RD(InsnBase):
    pass
class X_WR(InsnBase):
    pass
class X_WR_INC(InsnBase):
    pass
class X_INC_WR(InsnBase):
    pass
class Q_RD_INC(InsnBase):
    pass
class Q_OFF_RD(InsnBase):
    pass
class Q_WR(InsnBase):
    pass
class Q_WR_INC(InsnBase):
    pass
class Q_A64LD(InsnBase):
    pass
class X2Q(InsnBase):
    pass
class Q2X(InsnBase):
    pass
class PREJR(InsnBase):
    pass
class ORL(InsnBase):
    pass
class ORH(InsnBase):
    pass
class ANDL(InsnBase):
    pass
class ANDH(InsnBase):
    pass
class XORL(InsnBase):
    pass
class XORH(InsnBase):
    pass
class MUL_i(InsnBase):
    pass
class DIV_i(InsnBase):
    pass
class ADD(InsnBase):
    pass
class ADDC(InsnBase):
    pass
class SUB(InsnBase):
    pass
class SUBC(InsnBase):
    pass
class OR(InsnBase):
    pass
class AND(InsnBase):
    pass
class XOR(InsnBase):
    pass
class ASR_i(InsnBase):
    pass
class ASR(InsnBase):
    pass
class SL_i(InsnBase):
    pass
class SL(InsnBase):
    pass
class SR_i(InsnBase):
    pass
class SR(InsnBase):
    pass
class NOP(InsnBase):
    pass
class CMP(InsnBase):
    pass
class MUL(InsnBase):
    pass
class DIV(InsnBase):
    pass
class SEL(InsnBase):
    pass
class SEL_i(InsnBase):
    pass
class BFGET_i(InsnBase):
    pass
class BFSET_i(InsnBase):
    pass
class ST_FLG(InsnBase):
    pass
class SYSCALL(InsnBase):
    pass
class LD_FLG(InsnBase):
    pass
class LD_MDL(InsnBase):
    pass
class LD_MDH(InsnBase):
    pass

# Emitters
def emit_w32(addr, val):
    return [
        LD(a13, addr >> 16),
        LD(a12, addr),
        LD(a11, val >> 16),
        LD(a10, val),
        X_WR_i(0xffff, x10),
    ]

def emit_set_mpu(n, addr, size, perm=3):
    return [
        LD(a13, 0),
        LD(a12, 0xd804 + 8*n),
        LD(a11, addr >> 16),
        LD(a10, addr),
        X_WR_i(0xffff, x10),

        LD(a13, 0),
        LD(a12, 0xd800 + 8*n),
        LD(a11, size),
        LD(a10, perm),
        X_WR_i(0xffff, x10),
    ]

asm = []

'''
# make bootrom accessible from ARM
asm += emit_set_mpu(0, 0, 0xffff)
asm += emit_set_mpu(1, 0x10000, 0xffff)
asm += emit_set_mpu(2, 0x20000, 0xffff)
asm += emit_set_mpu(3, 0x30000, 0xffff)
for i in range(4, 8):
    asm += emit_set_mpu(i, 0, 0, 0)
'''

assert len(asm) == 0

# otp dumper
asm += [
    LD(sp, 0x2000),    # setup sp

    LD(a2, 0),              # unk
    LD(a3, 0x40),           # num_lines
    LD(a4, 0x2000),         # out_buf
    LD(a5, 0x1980),         # tmp_buf0
    LD(a6, 0x1990),         # tmp_buf1
    LD(a0, 0x39b3),         # a0 = rom_read_otp()
    PREJR(AL, 12, a0), # call a0
      LD(a0, 19),           # lr
      NOP(),
      X_INC_WR(sp, 0xf8, x2),
      X_INC_WR(sp, 0xf8, x6),
      X_INC_WR(sp, 0xf8, x10),
      X_INC_WR(sp, 0xf8, xsp),
      INC_WR(sp, 0xfe, a2),
      INC_WR(sp, 0xfe, a3),
      INC_WR(sp, 0xfe, a4),
      INC_WR(sp, 0xfe, a5),
      INC_WR(sp, 0xf8, a6),
]

asm += emit_set_mpu(0, 0x2000, 0x100*8)

# inf loop
asm += [
    PREJ(AL, 2, 0),
    NOP(),
]

for insn in asm:
    print struct.pack('<I', insn.encode()).encode('hex')
