#!/bin/bash

while [[ $res == $null ]];
do
  res=`ps axf | grep execute | grep -v grep | grep -v waitfor.sh | awk '{print $1}'`
done 
gdb attach $res
