#!/bin/bash

role=$2

if [ $role == 'client' ]
then
    args="-h 10.0.0.1 -o $1.txt"
    echo "${args}"
fi

# case $1 in
#     "tcp")
#         ./NPtcp -p 0 -C 0 -l 1 -u 8192 -b 8192 -P 80 "${arg}"
#         ;;
#     "mtcp")
#         ./NPmtcp -p 0 -C 0 -l 1 -u 9000 -P 80 "${arg}"
#         ;;
#     "cygnus")
#         ./LD_LIBRARY_PATH=/home/yihan/cygnus/Cygnus:/home/yihan/cygnus/mthread:/home/yihan/Hoard \
#         ./NPcygnus -p 0 -C 0 -l 1 -u 8192 -P 80 "${arg}"
#         ;;
#     *)
#         echo "Wrong test!"
#         ;;
# esac
# wait
