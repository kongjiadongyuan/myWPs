def bb
    b *(0x0000555555554000+$arg0)
end

def bbc
    b *(0x0000000000000B02+0x0000555555554000)
    continue
end

def tcode
    x/150i 0x0000133700000000
end

def tdata
    x/150i 0x0000414100000000
end

handle SIGALRM nostop
