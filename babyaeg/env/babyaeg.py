#!/bin/python
import sys, os, random, base64, time
from threading import Timer

TIME = 5
nonce = 0

def sanitize(arg):
    for c in arg:
        if c not in '1234567890abcdefABCDEF':
            return False
    return True

class MyTimer():
    timer=None
    def __init__(self):
        self.timer = Timer(TIME, self.dispatch, args=[])
        self.timer.start()
    def dispatch(self):
        print 'time expired! bye!'
        sys.stdout.flush()
        os.system('rm /tmp/{0}'.format(nonce))
        os._exit(0)


if __name__ == '__main__':
    print '---------------------------------------------------'
    print '-  Welcome to QWB BABYAEG-'
    print '---------------------------------------------------'
    print 'I will send you a newly compiled binary (probably exploitable) in base64 format'
    print 'after you get the binary, I will be waiting for your input as a plain text'
    print 'when your input is given, I will execute the binary with your input as argv[1]'
    print 'you have {0} seconds to build exploit payload'.format(TIME)
    print 'hint: base64 -d 1.bin | gunzip > 1.elf'
    print 'wait...'
    sys.stdout.flush()
    time.sleep(5)

    nonce = random.randrange(100000000000000000)
    cmd = 'python generate.py {0} > /dev/null 2> /dev/null'.format(nonce)
    #print (cmd)
    os.system('python generate.py {0} > /dev/null 2> /dev/null'.format(nonce))
    os.system('cat /tmp/{0} | compress > /tmp/{0}.Z'.format(nonce))
    dat = open('/tmp/{0}.Z'.format(nonce)).read()
    os.system('rm /tmp/{0}.Z'.format(nonce))
    MyTimer()
    print base64.b64encode(dat)
    sys.stdout.flush()
    print '\nhere, get this binary and give me some crafted argv[1] for explotation'
    print 'remember you only have {0} seconds... hurry up!'.format(TIME)
    sys.stdout.flush()
    sys.stdin.flush()
    arg = raw_input()
    if sanitize(arg)!=True :
        print "don't bother your self with tricking bash command line :)"
        print "bash special characters will be filtered"
        sys.stdout.flush()
        os.system('rm /tmp/{0}'.format(nonce))
        os._exit(0)
    else:
        print 'executing the binary with your input {0}...'.format(arg)
        os.system('/tmp/{0} {1}'.format(nonce, arg))
        os.system('rm /tmp/{0}'.format(nonce))

    print 'end of BABYAEG task. did you get a shell?'
    sys.stdout.flush()
    os._exit(0)
