# network
some scripts for computer etwork learning

## pktanalyzer 
### (for analyzing .pcap network packets)
Use command "python3 pktanalyzer.py -r filename.pcap" to execute the program.

To use these filters, add arguments like -tcp, -net 123.1.2.0, -c 5, -port 80 to the command.
You can use multiply filters in one command.

For example:
python3 pktanalyzer.py -r packets.pcap -c 3 -tcp -host 2.2.2.2</br>
python3 pktanalyzer.py -r packets.pcap -tcp -udp
python3 pktanalyzer.py -r packets.pcap -tcp -udp -net 123.21.31.0
python3 pktanalyzer.py -r packets.pcap -port 137 -udp -port 8888

You will get information of the packets that satisfy the filter you choose.

## myping and mytraceroute 
### (for simulating the behaviors of Linux command 'ping' and 'traceroute')
Use command "sudo python3 mytraceroute.py [host]" and
"sudo python3 myping.py [host]" to execute the programs.

Need sudo to run the programs (because of using raw socket)!

Examples to use options (lost responses will be printed as "*"):
sudo python3 myping.py [host] -c 5 -i 2 -s 64 -t 12
sudo python3 mytraceroute.py [host] -S -q 4
sudo python3 mytraceroute.py [host] -n -q 2
sudo python3 mytraceroute.py [host] -n
