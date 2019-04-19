import requests
from pwn import *
import os
context.arch = 'amd64'

def reg_helper(reg1, reg2):
    return (reg2 & 0x7) | ((reg1 & 0x7) << 3)

class Translator:
    def __init__(self):
        self.content = ''
        self.count = 0
    
    def start(self, cont = ''):
        self.content += cont
        return

    def getloop(self):
        return self.count

    def complete(self):
        self.content += '\x00'
        ulen = len(self.content)
        self.content = p64(ulen) + self.content
    

    def movsxd(self, rx, ryd):
        self.content += '\x01'
        self.content += chr(0xc0 | reg_helper(ryd, rx))
        self.count += 2
    
    def add(self, rx, ry):
        # \x02
        # add rx, ry
        self.content += '\x02'
        self.content += chr(0xc0 | reg_helper(ry, rx))
        self.count += 2
    
    def sub(self, rx, ry):
        # \x03
        # sub rx, ry
        self.content += '\x03'
        self.content += chr(0xc0 | reg_helper(ry, rx))
        self.count += 2
    
    def uand(self, rx, ry):
        # \x04
        # and rx, ry
        self.content += '\x04'
        self.content += chr(0xc0 | reg_helper(ry, rx))
        self.count += 2
    
    def shl(self, rx, ryd):
        # \x05
        # mov cl, ryd
        # shl rx, cl
        self.content += '\x05'
        self.content += chr(0xc0 | reg_helper(ryd, rx))
        self.count += 2

    def shr(self, rx, ryd):
        # \x06
        # mov cl, ryd
        # shr rx, cl
        self.content += '\x06'
        self.content += chr(0xc0 | reg_helper(ryd, rx))
        self.count += 2

    def mov(self, rx, ry):
        self.content += '\x07'
        self.content += chr(0xc0 | reg_helper(ry, rx))
        self.count += 2

    def movc(self, rx, const):
        self.content += '\x08'
        self.content += chr(0xc0 | reg_helper(0, rx))
        self.content += p32(const)
        self.count += 6
    


    def load(self, rx, ryd):
        # mov eax, ryd
        # mov rx, [0x414100000000 + rax * 1]
        self.content += '\x09'
        self.content += chr(0xc0 | reg_helper(ryd, rx))
        self.count += 2
    
    def store(self, rx, ryd):
        # mov eax, rxd
        # mov [rdi + rax * 1], ry
        self.content += '\x0a'
        self.content += chr(0xc0 | reg_helper(ryd, rx))
        self.count += 2
    
    def bc(self, rchoice = 0):
        # input r8d, r9d, r10d, r11d
        # output r8
        self.content += '\x0b'
        self.content += chr(rchoice)
        self.count += 2
    
    def time(self, rchoice = 0):
        # input r8d, r9d, r10d, r11d
        # output r8
        self.content += '\x0b'
        self.content += chr(rchoice + 8)
        self.count += 2
    
    def builtin(self, choice):
        self.content += '\x0b'
        self.content += chr(choice)

    def loop(self, count, offset, reg = 0):
        self.content += '\x0c'
        self.content += chr(reg * 0x8)
        self.content += p32(count)
        self.content += p32(offset)
        self.count += 10

    def go(self):
        token = keyget()
        filename = 'tmptmp'
        os.system('touch ' + filename)       
        open('tmptmp', 'w').write(self.content)
        result = upload(token, filename)
        os.system('rm ' + filename)
        result = result.split('\n')
        result = result[1:-1]
        r = []
        for tmp1 in result:
            tmp1 = tmp1.split(' ')
            tmp1 = tmp1[:-1]
            for tmp2 in tmp1:
                r.append(int(tmp2, 16))
        return r 



# def upload(token,filename):
#     url = 'http://spectre.pwni.ng:4000'
#     files = {'script': open(filename, 'rb')}
#     data = {'pow':token}
#     r = requests.post(url, files=files, data=data)
#     res = r.content
#     pos = res.find('<pre style="background-color: white; margin: 2rem 0; padding: 2rem 0">') + len('<pre style="background-color: white; margin: 2rem 0; padding: 2rem 0">')
#     res = res[pos:]
#     pos = res.find('</pre>')
#     res = res[:pos]
#     return res

def upload(token,filename):
    url = 'http://spectre.pwni.ng:4000'
    files = {'script': open(filename, 'rb')}
    data = {'pow':token}
    r = requests.post(url, files=files, data=data,  allow_redirects = False)
    url = r.headers['Location']
    while True:
        r = requests.get(url)
        res = r.content
        if(res.find('Processing')==-1):
            break
    pos = res.find('<pre style="background-color: white; margin: 2rem 0; padding: 2rem 0">') + len('<pre style="background-color: white; margin: 2rem 0; padding: 2rem 0">')
    res = res[pos:]
    pos = res.find('</pre>')
    res = res[:pos]
    return res



def keyget():
    keys = open('./keys.txt').read()
    keys = keys.split('\n')[:-1]
    result = keys.pop()
    f = open('./keys.txt', 'w')
    for i in keys:
        f.write(i)
        f.write('\n')
    f.close()
    return result