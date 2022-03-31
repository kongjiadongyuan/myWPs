import os, sys, time
import random
import string

def r(i):
    return random.randrange(i)

def e():
    return '(unsigned char)(a+{0})=={1} && (unsigned char)({2}*a-b)=={3} && (unsigned char)({4}*a+{5}*b-c)=={6}'.format(r(100),r(100),r(100),r(100),r(100),r(100),r(100))

def rs(length):
    return ''.join(random.sample(string.ascii_letters + string.digits, length))

def ra(start, end):
    items = [i for i in range(start, end)]
    random.shuffle(items)
    return str(items).strip('[').strip(']')

def ri(start, end):
    return random.randint(start, end)

s0=''
s1=''
s2=''
s3=''
s4=''
s5=''
s6=''
s7=''
s8=''
s9=''
s10=''
s11=''
s12=''
s13=''
s14=''
s15=''
s16=''

if r(2)==1:
        s0='//'
if r(2)==1:
        s1='//'
if r(2)==1:
        s2='//'
if r(2)==1:
        s3='//'
if r(2)==1:
        s4='//'
if r(2)==1:
        s5='//'
if r(2)==1:
        s6='//'
if r(2)==1:
        s7='//'
if r(2)==1:
        s8='//'
if r(2)==1:
        s9='//'
if r(2)==1:
        s10='//'
if r(2)==1:
        s11='//'
if r(2)==1:
        s12='//'
if r(2)==1:
        s13='//'
if r(2)==1:
        s14='//'
if r(2)==1:
        s15='//'
if r(2)==1:
        s16='//'

if len(sys.argv)!=2 :
    print 'python generate.py [nonce]'
    sys.exit(0)

print rs(8), ra(0, 5), ra(5, 10), ra(0, 10), ra(0, 10), ra(11, 20), ra(0, 0x80), ra(0, 0x80), ra(0x30, 0xb0), ri(5, 9), ri(11, 19), ri(0x30, 0xaf)
name = sys.argv[1]
source = open('source').read()
fsource = source.format(r(8192),r(256),r(256),r(16),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16, '"'+rs(8)+'"', ra(0, 5), ra(5, 10), ra(0, 10), ra(0, 10), ra(11, 20), ra(0, 0x40), ra(0, 0x40), ra(0x30, 0x70), ri(5, 9), ri(11, 19), ri(0x30, 0x6f))
#fsource = source %(r(8192),r(256),r(256),r(16),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),e(),s0,s1,s2,s3,s4,s5,s6,s7,s8,s9,s10,s11,s12,s13,s14,s15,s16, rs(8), ra(0, 5), ra(5, 10), ra(0, 10), ra(0, 10), ra(11, 20), ra(0, 0x80), ra(0, 0x80), ra(0x30, 0xb0), ri(5, 9), ri(11, 19), ri(0x30, 0xaf))
#print fsource
open('/tmp/{0}.c'.format(name), 'w').write( fsource )
os.chdir('/tmp')
os.system('gcc -o /tmp/{0} /tmp/{0}.c -fno-stack-protector -Ttext=0x{1}000 -no-pie'.format(name, r(9999)))
os.system('strip /tmp/{0}'.format(name))
os.system('rm /tmp/{0}.c'.format(name))
#file = '/tmp/{0}.c'.format(name)
#print (file)
