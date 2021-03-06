# Router-packet-simulator
The python files are just the checker for the router that is written in C++.<br/>
Used the Internet Protocol (IP) and the Ethernet/Industry Protocol (IP, I know, funny coincidence) to implement the ARP and ICMP protocols on a simulated router.<br/>
The really nice part is the lookup time in the routing table that is very efficient. The lookup time is asymptotically O(1) by using the following data structure: a vector of 32 elements, and those elements are hash-tables.<br/>
Explanation:<br/>
A position in the vector represents the network mask and there are only 32 possible network masks (practically there are only 31 but to be rigorous I implemented for 32) and for an incoming packet I must find on which interface to send it by making a logical AND between the destination IP and a network mask, prioritizing the smaller masks first. So I start in the vector from the 32nd element and see if the result of destination_IP &amp; mask is in the hash-table. If it is, I found where to send the package. If not, I look further at the bigger masks.<br/>
TLDR: because I hold my information in a vector of size 32 which has hash-tables as it's elements and my information is in those hash-tables, I can extract the information in a constant time.
