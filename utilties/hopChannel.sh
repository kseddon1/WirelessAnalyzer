#!/bin/bash

infinite_loop=1


#typical 2.4Ghz non-overlapping channel list
#channels=1,6,11

#5Ghz non-dfs channel list
#channels=40,44,48,52,149,153,157,161

#5Ghz non-overlapping channel list
channels=36,40,44,48,52,56,60,100,104,108,112,116,120,124,128,132,136,140,149,153,157,161

while [ $infinite_loop -eq 1 ]
do

    for channel in ${channels//,/ }
    do
        sleep 1 
      #echo 'set channel to'
      #echo $channel
        sudo iw dev wlan1mon set channel $channel HT20
    done

done

