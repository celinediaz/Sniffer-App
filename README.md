# SnifferProject
 C++ Sniffer App using MFC and npcap made for a System Programming class.
 To be able to use it you might need to set up the MFC environment. Which is only available on Windows.
 Some libraries used were jsoncpp and npcap so that is necessary too.
 
 
 
FEATURES:
- Capturing and analyzing ipv4, ipv6 and ARP packets. 
- Selecting the interface (since it only analyzes ipv4, ipv6 and arp then you'd need to use the wifi interface)
- Select a packet to show a more detailed analysis. (hexdump in ascii, binary, hex; list with its info; graphic header)
- Filter by size, EtherType and IP address.
- Show the stats of the size of the captured packets.
- Save the captured packet to a json file.

Also, it works by reading and writing each packet into a file, it could be faster if I didn't do that and just added it directly into a vector, but this worked as practice on reading and writing, so this could be seen as a feature. After all this was a project meant for learning.

The original source code used to make the function that captures the packets
(int  CSnifferProjectDlg::captura()) was on the npcap SDK examples and belongs to:
Copyright (c) 1999 - 2005 NetGroup, Politecnico di Torino (Italy)
Copyright (c) 2005 - 2006 CACE Technologies, Davis (California)

 
