# Marvell FIGO disassembler
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
    [ "X.RD.i"  , "C,xT"        , "0111CCCCCCCCCCCCTT00CCCC" ],
    [ "X.WR.i"  , "C,xT"        , "0111CCCCCCCCCCCCTT-1CCCC" ],
    [ "X.WR.i"  , "C,xT"        , "0111CCCCCCCCCCCCTT01CCCC" ],
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

# Instruction objects
class Instruction:
    def __init__(self, mnemonic, operands):
        self.mnemonic = mnemonic
        self.operands = operands

class Operand:
    pass

class OperandReg(Operand):
    def __init__(self, name):
        self.name = name
    def to_str(self):
        return self.name

class OperandCond(Operand):
    def __init__(self, cond):
        self.cond = cond
    def to_str(self):
        return self.cond

class OperandImm(Operand):
    def __init__(self, imm, imm_raw):
        self.imm = imm
        self.imm_raw = imm_raw
    def to_str(self):
        if self.imm >= 0:
            return '0x%x' % (self.imm)
        else:
            return '0x%x [-0x%x]' % (self.imm_raw, -self.imm)

# Instruction decoders
class OperandDecoder:
    @staticmethod
    def get_mask_and_shift(prototype, letter):
        mask = ''
        for bit in prototype[2]:
            if bit == letter:
                mask  = mask + '1'
            else:
                mask  = mask + '0'
        shift = len(mask) - 1 - mask.rfind('1')
        return (int(mask, 2), shift)

    def __init__(self, prototype, letter):
        self.letter = letter
        self.mask, self.shift = self.get_mask_and_shift(prototype, letter)

    def decode_as_int(self, insn):
        return (insn & self.mask) >> self.shift

class OperandDecoder_Sparse:
    @staticmethod
    def get_sparse_extraction_map(prototype, letter):
        bit_positions = []
        for n, bit in enumerate(prototype[2]):
            if bit == letter:
                bit_positions += [ 23 - n ]
        return list(reversed(bit_positions))

    def __init__(self, prototype, letter):
        self.letter = letter
        self.extraction_map = self.get_sparse_extraction_map(prototype, letter)

    def decode_as_int(self, insn):
        value = 0
        for i in range(len(self.extraction_map)):
            value |= ((insn >> self.extraction_map[i]) & 1) << i
        return value

class OperandDecoder_Reg(OperandDecoder):
    def decode(self, insn):
        return OperandReg(REGISTERS[self.decode_as_int(insn)])

class OperandDecoder_QReg(OperandDecoder):
    def decode(self, insn):
        return OperandReg('q%u' % self.decode_as_int(insn))

class OperandDecoder_XReg(OperandDecoder):
    def decode(self, insn):
        return OperandReg(REGISTERS_X[self.decode_as_int(insn)])

class OperandDecoder_Cond(OperandDecoder):
    def decode(self, insn):
        return OperandCond(CONDITIONS[self.decode_as_int(insn)])

def sign_ext(imm, bit_width):
    if imm & (1 << (bit_width - 1)):
        imm = -((imm ^ ((1 << bit_width) - 1)) + 1)
    return imm

class OperandDecoder_Imm(OperandDecoder_Sparse):
    def __init__(self, prototype, letter, signed=False):
        OperandDecoder_Sparse.__init__(self, prototype, letter)
        self.signed = signed

    def decode(self, insn):
        imm = None
        imm_raw = self.decode_as_int(insn)

        if self.signed:
            bit_width = len(self.extraction_map)
            imm = sign_ext(imm_raw, bit_width)
        else:
            imm = imm_raw

        return OperandImm(imm, imm_raw)

class InstructionDecoder:
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
    def build_operand_decoders(prototype):
        operand_decoders = []
        for operand in prototype[1].split(','):
            if operand == '':
                continue
            if prototype[0] in ['PREJ', 'PREJR', 'SEL', 'SEL.i', 'SEL.x'] and operand == 'C':
                # Special case for cond-codes
                operand_decoders += [OperandDecoder_Cond(prototype, operand[0])]
            elif operand.startswith('r'):
                operand_decoders += [OperandDecoder_Reg(prototype, operand[1])]
            elif operand.startswith('q'):
                operand_decoders += [OperandDecoder_QReg(prototype, operand[1])]
            elif operand.startswith('x'):
                operand_decoders += [OperandDecoder_XReg(prototype, operand[1])]
            elif operand.startswith('N') or operand.startswith('M'):
                operand_decoders += [OperandDecoder_Imm(prototype, operand[0], signed=True)]
            else:
                operand_decoders += [OperandDecoder_Imm(prototype, operand[0])]
        return operand_decoders

    def __init__(self, prototype):
        self.mnemonic = prototype[0]
        self.mask, self.value = self.get_mask_and_value(prototype)
        self.operand_decoders = self.build_operand_decoders(prototype)

    def decode(self, insn):
        if (insn & self.mask) != self.value:
            return None
        operands = [op.decode(insn) for op in self.operand_decoders]
        return Instruction(self.mnemonic, operands)

INSTRUCTION_DECODERS = []
for proto in INSTRUCTION_PROTOTYPES:
    INSTRUCTION_DECODERS += [ InstructionDecoder(proto) ]

# Tests
assert OperandDecoder.get_mask_and_shift([0, 0, 'AAAA0000'], 'A') == (0xF0, 4)
assert OperandDecoder_Sparse.get_sparse_extraction_map([0, 0, 'A0AA0000'], 'A') == [20, 21, 23]
assert InstructionDecoder.get_mask_and_value([0, 0, '1100---1']) == (0xF1, 0xC1)

# Formatter
class AsmLine:
    def __init__(self, addr, opcode, insn):
        self.addr = addr
        self.opcode = opcode
        self.insn = insn
        self.comment = ''
        self.indentation = 4
        self.xrefs = []

    def get(self):
        line = ''
        line += '%08x  ' % self.addr
        line += '%06x  ' % self.opcode
        line += ' ' * self.indentation
        line += self.insn.mnemonic
        line += ' '*(36 - len(line))
        line += ', '.join([op.to_str() for op in self.insn.operands])
        line += ' '*(64 - len(line))
        line += '; '
        line += self.comment
        if len(self.xrefs) > 0:
            line += 'XREF: ' + ', '.join(['0x%x' % x for x in self.xrefs])
        return line

class Formatter:
    @staticmethod
    def decode(insn):
        for decoder in INSTRUCTION_DECODERS:
            decoded_insn = decoder.decode(insn)
            if decoded_insn != None:
                return decoded_insn
        return Instruction('<invalid>', [])

    def __init__(self, file_path, base):
        self.base = base
        self.buf = open(file_path, 'rb').read()

    @staticmethod
    def indent_jumps(listing):
        for n, line in listing.items():
            if line.insn.mnemonic in ['PREJ', 'PREJR']:
                jmp_delay = line.insn.operands[1].imm
                for i in range(1, jmp_delay):
                    listing[n+i].indentation += 2

    @staticmethod
    def simplify_stack_operations(listing):
        for n, line in listing.items():
            simple_mnemonic = 'PUSH' if ('WR' in line.insn.mnemonic) else 'POP'
            if line.insn.mnemonic == 'X.INC.WR':
                if line.insn.operands[0].name != 'sp':
                    continue
                if line.insn.operands[1].imm != -8:
                    continue
                line.insn.mnemonic = 'X.PUSH'
                line.insn.operands = [ line.insn.operands[2] ]
            if line.insn.mnemonic == 'X.RD.INC':
                if line.insn.operands[0].name != 'sp':
                    continue
                if line.insn.operands[1].imm != 8:
                    continue
                line.insn.mnemonic = 'X.POP'
                line.insn.operands = [ line.insn.operands[2] ]
            if line.insn.mnemonic == 'INC.WR':
                if line.insn.operands[0].name != 'sp':
                    continue
                if line.insn.operands[1].imm != -2:
                    continue
                line.insn.mnemonic = 'PUSH'
                line.insn.operands = [ line.insn.operands[2] ]
            if line.insn.mnemonic == 'RD.INC':
                if line.insn.operands[0].name != 'sp':
                    continue
                if line.insn.operands[1].imm != 2:
                    continue
                line.insn.mnemonic = 'POP'
                line.insn.operands = [ line.insn.operands[2] ]

    @staticmethod
    def resolve_jumps(listing):
        a0_load_value = None
        a0_load_addr = None
        a1_load_value = None
        a1_load_addr = None
        last_xsp_pop = None
        for n, line in listing.items():
            if line.insn.mnemonic == 'LD':
                if line.insn.operands[0].name == 'a0':
                    a0_load_value = line.insn.operands[1].imm
                    a0_load_addr = n
                if line.insn.operands[0].name == 'a1':
                    a1_load_value = line.insn.operands[1].imm
                    a1_load_addr = n
            if line.insn.mnemonic == 'X.POP':
                if line.insn.operands[0].name == 'xsp':
                    last_xsp_pop = n
            jmp_dst = None
            jmp_src = None
            if line.insn.mnemonic == 'PREJR':
                jmp_delay = line.insn.operands[1].imm
                jmp_reg = line.insn.operands[2].name
                jmp_src = n+jmp_delay-1
                if jmp_reg == 'a0':
                    if a0_load_addr and (n - a0_load_addr < 2):
                        jmp_dst = a0_load_value
                    elif last_xsp_pop and (n - last_xsp_pop < 2):
                        jmp_dst = 'RETURN'
                elif jmp_reg == 'a1':
                    if a1_load_addr and (n - a1_load_addr < 2):
                        jmp_dst = a1_load_value
            elif line.insn.mnemonic == 'PREJ':
                jmp_delay = line.insn.operands[1].imm
                jmp_src = n+jmp_delay-1
                jmp_imm = line.insn.operands[2].imm
                jmp_dst = n + sign_ext(jmp_imm, 8)
            if jmp_dst:
                if jmp_dst == 'RETURN':
                    listing[jmp_src].comment += '<subroutine return>'
                else:
                    if jmp_dst in listing:
                        if jmp_dst < jmp_src and abs(jmp_dst - jmp_src) < 16:
                            listing[jmp_dst].comment += '<+ '
                            for i in range(jmp_dst+1, jmp_src):
                                listing[i]  .comment += ' | '
                            listing[jmp_src].comment += '-+ '
                        else:
                            listing[jmp_dst].xrefs += [jmp_src]
                            listing[jmp_src].comment += ('JMP 0x%x' % jmp_dst)
                    else:
                        listing[jmp_src].comment += ('CALL ROM_0x%x' % jmp_dst)

    @staticmethod
    def heuristic_simplify_writes(listing):
        loads = {}
        for n, line in listing.items():
            if line.insn.mnemonic == 'LD':
                reg = line.insn.operands[0].name
                loads[reg] = (n, line.insn.operands[1].imm_raw)
            if line.insn.mnemonic == 'X.WR.i':
                dst_addr = line.insn.operands[0].imm_raw
                if line.insn.operands[1].name == 'x10':
                    values = []
                    for reg in ['a10', 'a11', 'a12', 'a13']:
                        if reg in loads and abs(loads[reg][0] - n) < 8:
                            values += [loads[reg][1]]
                        else:
                            values += [0]
                    if dst_addr == 0xffff:
                        width = 'u32'
                        dst_addr = values[2]
                        values   = values[:2]
                    else:
                        width = 'u64'
                    value = 0
                    for x in values[::-1]:
                        value <<= 16
                        value |= x
                    line.comment += '[0x%x, %s] = 0x%x' % (dst_addr, width, value)

    @staticmethod
    def simplify_movs(listing):
        for n, line in listing.items():
            if line.insn.mnemonic.startswith('SEL'):
                if line.insn.operands[1].cond == 'AL':
                    line.insn.mnemonic = line.insn.mnemonic.replace('SEL', 'MOV')
                    line.insn.operands = [line.insn.operands[0], line.insn.operands[3]]

    def go(self):
        listing = {}
        for i in range(len(self.buf)//4):
            opcode = struct.unpack('<I', self.buf[4*i : 4*i+4])[0]
            insn = self.decode(opcode)
            listing[self.base + i] = AsmLine(self.base + i, opcode, insn)
        self.indent_jumps(listing)
        self.simplify_stack_operations(listing)
        self.resolve_jumps(listing)
        self.simplify_movs(listing)
        #self.heuristic_simplify_writes(listing)
        for n in sorted(listing.keys()):
            print(listing[n].get())

base = 0
if len(sys.argv) > 2:
    base = int(sys.argv[2], 0)

fmt = Formatter(sys.argv[1], base)
fmt.go()
