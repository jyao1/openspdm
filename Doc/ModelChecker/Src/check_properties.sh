#!/bin/bash
echo Hello World!
spin -a spdm_ver7_content.pml
cc -DNOREDUCE -DVECTORSZ=1000000 -g -o pan pan.c
counter=0
while [ $counter -le 83 ]
do
    if [ $counter == '65' ] || [ $counter == '67' ] || [ $counter == '68' ] || [ $counter == '69' ] || [ $counter == '71' ] || [ $counter == '73' ] || [ $counter == '77' ];
    then
        echo $counter is $counter
        ((counter++))
        continue
    fi
    echo $counter
    ./pan -m9999999 -a -n  -N p$counter
    ((counter++))
done
