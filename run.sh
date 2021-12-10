#!/bin/bash

role=$2

if [ $role == 'client' ]
then
    args="-h 10.0.0.1 -o $1.txt"
fi

case $1 in
    "tcp")
        ./NPtcp -p 0 -C 0 -l 1 -u 8192 -b 8192 -P 80 -n 1024 "${args}"
        ;;
    "mtcp")
        ./NPmtcp -p 0 -C 0 -l 1 -u 9000 -P 80 -n 1024 "${args}"
        ;;
    "cygnus")
        LD_LIBRARY_PATH=/home/yihan/cygnus/Cygnus:/home/yihan/cygnus/mthread:/home/yihan/Hoard \
        ./NPcygnus  --perturbation=0 --start=1 --end=32768 --port=80 --repeat=1024 --host=10.0.0.1 --output=cygnus.txt \
                    --num_cores=1 --test_time=120 --config_path=/home/yihan/cygnus/test/config
        ;;
    *)
        echo "Wrong test!"
        ;;
esac
wait
