from elftools.elf.elffile import *
import os
from capstone import *
from pwn import *

def get_ehframe_vaddr(elffile):
    ehframe = elffile.get_section_by_name('.eh_frame')
    vaddr = ehframe.header['sh_addr']
    return vaddr

def logic2physic(elffile, addr):
    for s in elffile.iter_segments():
        baseaddr = s.header['p_vaddr']
        size = s.header['p_memsz']
        if addr >= baseaddr and addr <= baseaddr + size:
            offset = addr - baseaddr
            physicaddr = s.header['p_offset'] + offset
            return physicaddr
    raise Exception('logic2physic: addr not found.')

def physic2logic(elffile, addr):
    for s in elffile.iter_segments():
        baseaddr = s.header['p_offset']
        size = s.header['p_memsz']
        if addr >= baseaddr and addr <= baseaddr + size:
            offset = addr - baseaddr
            logicaddr = s.header['p_vaddr'] + offset
            return logicaddr
    raise Exception('physic2logic: addr not found')

def get_call_vaddr(f, elffile, vaddr):
    paddr = logic2physic(elffile, vaddr)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    f.seek(paddr)
    content = f.read(0x30)
    oplist = []
    for ins in md.disasm(content, vaddr):
        oplist.append(ins)
    if not oplist[0].mnemonic == 'call':
        raise Exception("get_call_vaddr: instruction is not call.")
    call_vaddr = int(oplist[0].op_str, 16)
    next_vaddr = oplist[1].address
    return call_vaddr, next_vaddr

def generatecode(ehframevaddr, callvaddr):
    context.arch = 'amd64'
    res = ''
    res += asm('push rbp')
    res += asm('mov rbp, rsp')
    res += asm('sub rsp, 0x8')
    res += asm('push rdi')
    res += asm('push rsi')
    res += asm('push rdx')
    res += asm('push rax')
    res += asm('xor rax, rax')
    res += asm('xor rdi, rdi')
    res += asm('lea rsi, [rbp - 0x8]')
    res += asm('mov rdx, 1')
    res += asm('syscall')
    res += asm('pop rax')
    res += asm('pop rdx')
    res += asm('pop rsi')
    res += asm('pop rdi')
    tmp = len(res)
    tmp += 5 
    print hex(ehframevaddr)
    print hex(tmp)
    tmp += ehframevaddr 
    tmp = callvaddr - tmp 
    if tmp < 0:
        tmp = 0x100000000 + tmp
    res += '\xe8' + p32(tmp)
    res += asm('leave')
    res += asm('ret')
    return res

def patch(f, elffile, shellcode, ehframevaddr, patchvaddr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    patchpaddr = logic2physic(elffile, patchvaddr)
    f.seek(patchpaddr)
    content = f.read(0x20)
    oplist = []
    for ins in md.disasm(content, patchvaddr):
        oplist.append(ins)
    tmp = oplist[1].address
    tmp = ehframevaddr - tmp
    if tmp < 0:
        tmp = 0x100000000 + tmp 
    offset = tmp 
    tmp = oplist[1].address
    tmp = logic2physic(elffile, tmp)
    tmp = tmp - 4
    f.seek(tmp)
    f.write(p32(offset))
    ehframepaddr = logic2physic(elffile, ehframevaddr)
    f.seek(ehframepaddr)
    f.write(shellcode)

def hook(binaryname, patchvaddr):
    os.system('cp ' + binaryname + ' ' + binaryname + '.bak')
    f = open(binaryname, 'r+w')
    elffile = ELFFile(f)
    ehframevaddr = get_ehframe_vaddr(elffile)
    calladdr, nextaddr =  get_call_vaddr(f, elffile, patchvaddr)
    shellcode = generatecode(ehframevaddr, calladdr)
    # md = Cs(CS_ARCH_X86, CS_MODE_64)
    # for i in md.disasm(shellcode, 0x0000000000701A58):
    #     print i.mnemonic, i.op_str 
    patch(f, elffile, shellcode, ehframevaddr, patchvaddr)
    f.close()
    
if __name__ == '__main__':
    hook('binaries/binary0', 0x00000000080217D6)
