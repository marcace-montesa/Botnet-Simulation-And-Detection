#!bin/bash

signal=KILL

sleep_a_while () {
    sleep 30s 
}

sleep_a_bit () {
    sleep 5s 
}


# Note: command launched in background:
snort -dev -i eth0 -l final -c final.rules 2>/dev/null &

# Save PID of command just launched:
last_pid=$!

# Sleep for a while:
sleep_a_while
kill -9 $last_pid

python3 defender.py

sleep_a_bit
iptables -L

sleep_a_while
iptables -F

sleep_a_bit
iptables -L
