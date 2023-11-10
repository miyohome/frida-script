from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# 待反汇编的机器码
machine_code = b'\x55\x48\x8b\x05\xb8\x13\x00\x00'

# 创建Capstone引擎
md = Cs(CS_ARCH_X86, CS_MODE_32)

# 反汇编指令
for insn in md.disasm(machine_code, 0x1000):
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
