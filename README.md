Packrat is an open source command-line packet analyzer that takes the pain out of reading raw .pcap files. Packrat gives you a clean, colorized summary of IP conversations, protocol 
breakdowns, and traffic detection.

After using tshark I just wanted something simpler. Something I could run and immediately understand what's happening in a capture without digging through documentation for flags.

If you are using this tool and have any suggestions, feel free to open an issue or reach out!


***NOTE 

    Packrat reports HTTP at the packet level, not the transaction level. What thjis means is that since there is no TCP reassmeblt, A single HTTP request/response may span multiple packets. This can lead to a higher number of packets according to Wireshark or other Networking tools
    
******