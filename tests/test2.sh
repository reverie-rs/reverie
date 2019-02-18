#! /bin/bash

echo "hello, world, mypid=$BASHPID" && sleep 1 &

(echo "fork a child, mypid=$BASHPID" && sleep 1 &)
