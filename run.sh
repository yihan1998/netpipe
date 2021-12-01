#!/bin/bash

arg=$2

case $1 in
    "tcp")
        ./NPtcp -p 0 -C 0 -l 1 -u 8192 -b 8192 -P 80 "${arg}"
        ;;
    "mtcp")
        ./NPmtcp -p 0 -C 0 -l 1 -u 9000 -P 80 "${arg}"
        ;;
    "cygnus")
        ./LD_LIBRARY_PATH=/home/yihan/cygnus/Cygnus:/home/yihan/cygnus/mthread:/home/yihan/Hoard \
        ./NPcygnus -p 0 -C 0 -l 1 -u 8192 -P 80 "${arg}"
        ;;
    *)
        echo "Wrong test!"
        ;;
esac
wait
