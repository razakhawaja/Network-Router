20100006 Mohammad Raza Khawaja
CS 4713 Assignment 1

What works and doesn't work:

1. Ping on two interfaces of the router (192.168.2.1 and 172.64.3.1). For some reason, it does not ping to the third interface (10.0.1.11)
and sends a destination net unreachable message. 
2. Ping to the two servers works. Traceroute from the two servers also works, although it displays some *'s in between which I am not sure why,
but the route is fine.
3. Pinging to an IP not configured on the network correctly sends ICMP Error message about destination net unreachable.
4. Downloading a file from one of the servers also works (client wget http://192.168.2.2 and on the other server too.)

There are 3 functions I implemented in sr_arpchache.c:
1. sr_arpcache_sweepreqs, which just traverses all requests and sends each of them to the handle_arpreq function.
2. handle_arpreq, which checks for timeouts for all packets on the current request. If there's a timeout, then all packets are
sent to the ICMPReplyHandler function which is responsible for sending error messages back to client. If there is no timeout,
then arpRequestSender function is called on the request, which broadcasts ARP requests from the router to get a reply back from a server.


In sr_router.c, I implemented several functions which are in the header file under my functions.
For any incoming packet, first check if it is IP or ARP. If it is IP, then I check if it was destined to one of router's interfaces.
If yes, then send an ICMP Echo back to the client through the echo handler func. If not destined to router's interface, then decrement TTL 
and send it to the func that handles packets not sent to router. Here, perform an LPM on the dest IP to find next hop IP. Use the arpcache to 
lookup its MAC address. If it was in the cache, then forward the packet to it. If not, add it to the cache, and sent it to the handle_arpreq func
so that the router can broadcast it and get to know where the packet was destined. 

If the incoming packet to the router was ARP, then I check if it was an ARP request or ARP reply. I have two functions that handle both accordingly. A request would come from the client when sending the packet to router, a reply would come after a response was received with the MAC address of a server.

--- I googled the algorithm for LPM, since I did not fully understand the part about masking.
--- I started coding using a top-down apprach by making empty functions that I would need later, so that is why there may seem some
	unneccessary functions that I could have just coded directly in a sequential style.
--- I wrote comments while I was writing code so you can get an idea of what I'm trying to do by just going through the code. 
