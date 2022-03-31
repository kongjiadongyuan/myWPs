from elftools.elf.elffile import *
from capstone import *
from pwn import u32

def parse_dynsym(elffile):
    dynsym = elffile.get_section_by_name('.dynsym').data()
    dynstr = elffile.get_section_by_name('.dynstr').data()
    strlist = ['None']
    for idx in range(len(dynsym) / 0x18):
        if idx == 0:
            continue
        else:
            sym = dynsym[idx * 0x18: idx * 0x18 + 0x18]
            offset = sym[:4]
            offset = u32(offset)
            tmpstr = dynstr[offset:].split('\x00')[0]
            strlist.append(tmpstr)
    return strlist

def parse_rela_plt(elffile, dynsym):
    rela_plt = elffile.get_section_by_name('.rela.plt').data()
    res = []
    for idx in range(len(rela_plt) / 0x18):
        tmp = rela_plt[idx * 0x18 + 12: idx * 0x18 + 16]
        tmp = u32(tmp)
        res.append(dynsym[tmp])
    return res

def parse_plt(elffile):
    strlist = parse_dynsym(elffile)
    strlist = parse_rela_plt(elffile, strlist)
    # print strlist 
    pltdata = elffile.get_section_by_name('.plt').data()
    pltaddress = elffile.get_section_by_name('.plt').header['sh_addr']
    oplist = []
    pltlist = {}
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(pltdata, pltaddress):
        oplist.append(ins)
    for ins in oplist:
        if ins.mnemonic == 'push':
            # print ins.mnemonic, ins.op_str
            addr = ins.address - 6
            try:
                stridx = int(ins.op_str, 16)
            except Exception:
                continue
            # print strlist[stridx]
            pltlist[strlist[stridx]] = addr 
    return pltlist
            

if __name__ == '__main__':
    f = open('binaries/binary19')
    elffile = ELFFile(f)
    print parse_dynsym(elffile)
    pltlist = parse_plt(elffile)
    for k in pltlist.keys():
        print k, hex(pltlist[k])
