/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *

 20100006 Mohammad Raza Khawaja
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>

#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"


/*---------------------------------------------------------------------
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 *
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr)
{
    /* REQUIRES */
    assert(sr);

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

int checkSumHandler(uint16_t oldS, uint16_t newS)
{
   if (oldS != newS)
   {
      printf("%s\n", "Packet got corrupted!" );
      return 0;
   }
   else
   {
    return 1;
   } 
}

int wasPacketSentToRouter(struct sr_instance* sr, sr_ip_hdr_t* iphdr)
{
  struct sr_if* iface_iter = sr->if_list;
  while(iface_iter != NULL)
  {
    if (iphdr->ip_dst == iface_iter->ip)
    {
      return 1;
    }
    else
    {
      iface_iter = iface_iter->next;
    }
  }
  return 0;
}

void TCPUDPHandler(struct sr_instance* sr, uint8_t* packet, sr_ip_hdr_t* ipHead, char* interface)
{
   if (ipHead->ip_p == 6 || ipHead->ip_p == 17) /* 6 for TCP, 17 for UDP */
   {
      printf("%s\n", "Request was not ICMP echo, it was TCP/UGP." );
      ICMPReplyHandler(sr, packet, ipHead, interface, 3, 3);
   }
   else
   {
      printf("%s\n", "Dont know what type of packet it is." );
      ICMPReplyHandler(sr, packet, ipHead, interface, 3, 3);
   } 

}

void ICMPReplyHandler(struct sr_instance* sr, uint8_t* packet, sr_ip_hdr_t* ipHead, char* interface, int type, int code)
{
 
  uint8_t* replyPacc = (uint8_t*)malloc(sizeof(sr_ip_hdr_t) + sizeof(sr_ethernet_hdr_t) + sizeof(sr_icmp_t3_hdr_t));
  long int ip_hdr_len,ether_hdr_len, t3_hdr_len;

  ether_hdr_len = sizeof(sr_ethernet_hdr_t); 
  ip_hdr_len = sizeof(sr_ip_hdr_t); 
  t3_hdr_len = sizeof(sr_icmp_t3_hdr_t); 
  int totalHdrLen = ether_hdr_len + ip_hdr_len + t3_hdr_len; 
   
  memcpy(replyPacc, packet, ip_hdr_len + ether_hdr_len);

  /*Making Ethernet header*/
  sr_ethernet_hdr_t* replyPacketEthHdr = (sr_ethernet_hdr_t*) replyPacc; 
  sr_ethernet_hdr_t* OriginalPacketEthHdr = (sr_ethernet_hdr_t*) packet;  

  replyPacketEthHdr->ether_type = htons(ethertype(packet));  
  memcpy(replyPacketEthHdr->ether_dhost, OriginalPacketEthHdr->ether_shost, ETHER_ADDR_LEN);  
  memcpy(replyPacketEthHdr->ether_shost, OriginalPacketEthHdr->ether_dhost, ETHER_ADDR_LEN);

  sr_ip_hdr_t* replyPacketIPHdr = (sr_ip_hdr_t*)(replyPacc+sizeof(sr_ethernet_hdr_t));

   /* Making reply packet IP header */
  struct sr_if* iface = sr_get_interface(sr, interface);
  replyPacketIPHdr->ip_len = htons(ip_hdr_len + t3_hdr_len);
  replyPacketIPHdr->ip_src = iface->ip;
  replyPacketIPHdr->ip_dst = ipHead->ip_src;
  replyPacketIPHdr->ip_off = htons(IP_DF); 
  replyPacketIPHdr->ip_id = htons(0);
  replyPacketIPHdr->ip_p = ip_protocol_icmp;
  replyPacketIPHdr->ip_sum = 0;
  replyPacketIPHdr->ip_ttl = 50;
  replyPacketIPHdr->ip_sum = cksum(replyPacketIPHdr,sizeof(sr_ip_hdr_t));

  /* Making reply packet ICMP Header */
  sr_icmp_t3_hdr_t* replyPaccICMP3 = (sr_icmp_t3_hdr_t*)(replyPacc + ether_hdr_len + ip_hdr_len);
  replyPaccICMP3->unused = 0;
  replyPaccICMP3->next_mtu = 0;
  replyPaccICMP3->icmp_type = type;
  replyPaccICMP3->icmp_code = code;
  memcpy(replyPaccICMP3->data, packet + ether_hdr_len, ICMP_DATA_SIZE);
  replyPaccICMP3->icmp_sum = 0;
  replyPaccICMP3->icmp_sum = cksum(replyPaccICMP3, t3_hdr_len);

  sr_send_packet(sr, replyPacc, totalHdrLen, interface);

  free(replyPacc);

   

}

void echoType8Handler(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, sr_ip_hdr_t* ipHead)
{
/* Make new reply ICMP packet, copy all revelent info from original packet into it and add new info */
    uint8_t* echoPacc = (uint8_t*)malloc(len);
    long int ip_hdr_len,ether_hdr_len;
    ether_hdr_len = sizeof(sr_ethernet_hdr_t); /*ethernet header size*/
    ip_hdr_len = sizeof(sr_ip_hdr_t); /*ip header length*/
   
   memcpy(echoPacc, packet, len);
   /* Making Ethernet Header */
   sr_ethernet_hdr_t* echoPacketEthHdr = (sr_ethernet_hdr_t*) echoPacc; /* Return packet eth header */
   sr_ethernet_hdr_t* OriginalPacketEthHdr = (sr_ethernet_hdr_t*) packet;  /* Original eth header */

   echoPacketEthHdr->ether_type = htons(ethertype(packet));  
   memcpy(echoPacketEthHdr->ether_dhost, OriginalPacketEthHdr->ether_shost, ETHER_ADDR_LEN);  
   memcpy(echoPacketEthHdr->ether_shost, OriginalPacketEthHdr->ether_dhost, ETHER_ADDR_LEN);
  
   /* Making IP header */
   sr_ip_hdr_t* echoPacketIPHdr = (sr_ip_hdr_t*) (echoPacc + ether_hdr_len);
   echoPacketIPHdr->ip_ttl = 50;
   echoPacketIPHdr->ip_p = ip_protocol_icmp;
   echoPacketIPHdr->ip_len = htons(len - ether_hdr_len);
   echoPacketIPHdr->ip_v = 4;
   echoPacketIPHdr->ip_off = htons(IP_DF);
   /* swapping dest and src */
   echoPacketIPHdr->ip_src = ipHead->ip_dst; 
   echoPacketIPHdr->ip_dst = ipHead->ip_src; 
   echoPacketIPHdr->ip_sum = 0; 
   echoPacketIPHdr->ip_sum = cksum(echoPacketIPHdr, ip_hdr_len); /*recompute IP checksum*/

  /* Making ICMP header*/
   sr_icmp_hdr_t* echoPacketICMPHdr = (sr_icmp_hdr_t*) (echoPacc + ether_hdr_len + ip_hdr_len);
   echoPacketICMPHdr->icmp_type = 0;
   echoPacketICMPHdr->icmp_code = 0; /* Code 0 for echo reply on router's interface. */
   echoPacketICMPHdr->icmp_sum = 0; /* Need to make it 0 so that old value doesnt effect the new sum */
   echoPacketICMPHdr->icmp_sum  = cksum(echoPacketICMPHdr, len - (ether_hdr_len + ip_hdr_len));

   sr_send_packet(sr, echoPacc, len , interface);
   free(echoPacc);
}


void IPHandlerFunc(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)

{
          printf("%s\n", "In IP handler function." );
              sr_ip_hdr_t* ipHead = (sr_ip_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t)); /* Move pointer to the IP header. */
              uint16_t oldSum = ipHead->ip_sum;
              ipHead->ip_sum = 0;

              uint16_t newSum = cksum(ipHead, sizeof(sr_ip_hdr_t));

              if (!checkSumHandler(oldSum, newSum)) /* checkSum failed */
              {
                printf("%s\n", "Packet was corrupted" );
              }
              else /* Checksum for IP header passed */
              {
                ipHead->ip_sum = newSum;
                /* Check if packet was destined to one of router's interfaces.*/
                if (wasPacketSentToRouter(sr, ipHead) == 1) /* It was destined to one of router's interfaces. */
                {
                    if (ipHead->ip_p == ip_protocol_icmp) /* It was an ICMP request. */
                    {
                        /* Move pointer to the ICMP header. */
                        sr_icmp_hdr_t* icmpHdr = (sr_icmp_hdr_t*) (packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));
                        
                         
                        uint16_t oldSum = icmpHdr->icmp_sum;
                        icmpHdr->icmp_sum = 0;
                        uint16_t newSum = cksum(icmpHdr, len - sizeof(sr_ethernet_hdr_t) - sizeof(sr_ip_hdr_t));

                        if (!checkSumHandler(oldSum, newSum)) 
                        {
                            printf("%s\n", "ICMP is corrupted." );
                            return;
                        } 
                        else /* ICMP is fine */
                        {
                            icmpHdr->icmp_sum = newSum;

                            if (icmpHdr->icmp_type == 8)
                            {
                              printf("%s\n", "Sending ICMP reply type 8" );
                              echoType8Handler(sr, packet, len, interface, ipHead);
                              return;
                            }
                            else
                            {
                              printf("%s\n", "Idk bro." );
                              return;
                            }
                        }
     
                    }
                    else /* Not an ICMP request, so its a TCP/UDP request. Generate a host unreachable message.*/
                    {
                        TCPUDPHandler(sr, packet, ipHead, interface); 
                    }

                }
                else /* Not destined for one of router's interfaces. */
                {
                    printf("%s\n", "Not destined to router's interfaces." );
                    ipHead->ip_ttl = ipHead->ip_ttl - 1; /* Decrement TTL */
                    ipHead->ip_sum = 0; 
                    ipHead->ip_sum = cksum(packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t)); /* Compute CheckSum again */
                    
                    if (ipHead->ip_ttl > 1)
                    {
                        printf("%s\n",  "Going to NotOnRoutersInterface Func");
                        NotOnRoutersInterface(sr, packet, len, interface, ipHead);
                    }
                    else
                    {
                        printf("%s\n", "Packet TTL expired." );
                        ICMPReplyHandler(sr, packet, ipHead, interface, 11, 0); /* Type 11 and Code 0 for TTL expired */
                    }
                    
                }

              }
          

}

struct sr_rt *LPM(struct sr_instance *sr, uint32_t ipDest) 

/* ----DISCLAIMER----

  Used an LPM algorithm I found on Stack Overflow because There were some things about the function
  that I did not completely understand. I understood an overview of LPM but the finer details, like why we are
  using masks and why are we using a bitwise.
   -------------------*/ 
{
  struct sr_rt* curr = sr->routing_table;
  struct sr_rt* lpmNode = NULL; 
 
  while (curr != NULL)
  {
    if ((curr->mask.s_addr & ipDest) == (curr->mask.s_addr & (curr->dest.s_addr)))
    {
      if (lpmNode == NULL) {
        lpmNode = curr;
      }
      else if (curr->mask.s_addr > (lpmNode->mask.s_addr)) 
      {
        lpmNode = curr;
      }
      
    }
    curr = curr->next;
  }
  return lpmNode;

}


void NotOnRoutersInterface(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface, sr_ip_hdr_t* ipHead)
{

     struct sr_rt *nextHop = LPM(sr, ipHead->ip_dst);
     printf("%s\n", "LPM function exited." );

      if (nextHop == NULL)
      {
          /* Match not found in table. Send ICMP Host unreachable 3,0 request.*/
          printf("%s\n", "Match not found. Send unreachable.");
          ICMPReplyHandler(sr, packet, ipHead, interface, 3, 0);    
      }
      else /* Match found. Forward the packet. */
      {
          printf("%s\n", "Next hop found.");
          struct sr_arpentry *nextMACAdd = sr_arpcache_lookup(&(sr->cache), nextHop->gw.s_addr);
          
          if (nextMACAdd)
          {
              printf("%s\n", "Cache hit!!!");
              sr_ethernet_hdr_t *forwardEth = (sr_ethernet_hdr_t*) packet;
              struct sr_if* interfaceOfLink = sr_get_interface(sr, nextHop->interface);
              
              unsigned char macAddrInterface[ETHER_ADDR_LEN];
              memcpy(macAddrInterface, interfaceOfLink->addr, ETHER_ADDR_LEN);
              memcpy(forwardEth->ether_shost, macAddrInterface, ETHER_ADDR_LEN);
              memcpy(forwardEth->ether_dhost, nextMACAdd->mac, ETHER_ADDR_LEN);

              free(nextMACAdd);
              sr_send_packet(sr, packet, len, interfaceOfLink->name);

          }
          else if (nextMACAdd == NULL)
          {
              printf("%s\n", "It was not found in cache. Queue a request to add to cache." );
              struct sr_arpreq * arpReq = sr_arpcache_queuereq(&(sr->cache), nextHop->gw.s_addr, packet, len, nextHop->interface);
              handle_arpreq(sr, arpReq);

          }      
      } 
    
}

void ARPReqHandler(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if * arrivalInterface, sr_arp_hdr_t * arpHead)
{
    /* Make ARP Request packet */
    uint8_t * ARPReqPacket = (uint8_t *) malloc(len); /* Make new packet to send back. */

    memcpy(ARPReqPacket, packet, len);
    /* Making ethernet header */
    sr_ethernet_hdr_t* ARPReq_EthHdr = (sr_ethernet_hdr_t*) ARPReqPacket;
    ARPReq_EthHdr->ether_type = htons(ethertype_arp); /* Set type to ARP. */

    /* Now the hardware address of interface from which it arrived becomes src, and hardware of source becomes dest. */
    sr_ethernet_hdr_t* originalEthHdr = (sr_ethernet_hdr_t*) packet; /* Get original ethernet header */

    unsigned char arrivalInterfaceAddr[ETHER_ADDR_LEN];
    memcpy(arrivalInterfaceAddr, arrivalInterface->addr, ETHER_ADDR_LEN);
    uint8_t  originalEthHdrSrcMac[ETHER_ADDR_LEN];
    memcpy(originalEthHdrSrcMac, originalEthHdr->ether_shost, ETHER_ADDR_LEN);

    memcpy(ARPReq_EthHdr->ether_shost, arrivalInterfaceAddr, ETHER_ADDR_LEN); 
    memcpy(ARPReq_EthHdr->ether_dhost, originalEthHdrSrcMac, ETHER_ADDR_LEN); 

    /* Making ARP Header now */

    sr_arp_hdr_t * ARPReq_arphdr = (sr_arp_hdr_t *) (ARPReqPacket + sizeof(sr_ethernet_hdr_t)); /* Move pointer to arp header start */
    memcpy(ARPReq_arphdr, arpHead, sizeof(sr_arp_hdr_t)); /* Copy all contents of original ARP header into new one */
              
    /* Now make necessary updates to Operation type and IP addresses. */
    ARPReq_arphdr->ar_op  = htons(arp_op_reply); /* It is now an ARP Reply, not a request. */
    ARPReq_arphdr->ar_sip = arrivalInterface->ip; /* Router Interface IP is now SRC IP of reply */
    ARPReq_arphdr->ar_tip = arpHead->ar_sip; /* Src IP of incoming is now target for outgoing */
    /* Now update the MAC addresses. */
    memcpy(ARPReq_arphdr->ar_tha, arpHead->ar_sha, ETHER_ADDR_LEN); /* Src MAC is now target MAC */
    memcpy(ARPReq_arphdr->ar_sha, arrivalInterface->addr, ETHER_ADDR_LEN); /* Router interface MAC is now Source MAC */
    sr_send_packet(sr, ARPReqPacket, len, arrivalInterface->name);
    printf("%s\n", "ARP Reply to a request successfully sent." );
    free(ARPReqPacket);
}

void ARPReplyHandler(struct sr_instance* sr, uint8_t * packet, unsigned int len, struct sr_if * arrivalInterface, sr_arp_hdr_t * arpHead)
{
    /* Insert into ARP Cache */
    struct sr_arpreq *cacheReq = sr_arpcache_insert(&(sr->cache), arpHead->ar_sha, arpHead->ar_sip); /* Src MAC and Src IP added to cache */

    printf("%s\n", "Now sending all outstanding packets waiting on this in the queue." );

    if (cacheReq ==  NULL)
    {
      printf("%s\n", "IP Not found in the request queue." );
      return;
    }
    else
    {
      struct sr_packet* currPacket = cacheReq->packets;
      while (currPacket)
      {
        /* uint8_t *ARPReplyPacket = currPacket->buf;  Try malloc */
        uint8_t *ARPReplyPacket = (uint8_t*)malloc(currPacket->len);
        memcpy(ARPReplyPacket, currPacket->buf, currPacket->len);

        unsigned int len1 = currPacket->len;
        sr_ethernet_hdr_t* ARPReply_EthHdr = (sr_ethernet_hdr_t*) ARPReplyPacket;

        memcpy(ARPReply_EthHdr->ether_dhost, arpHead->ar_sha, ETHER_ADDR_LEN);
        memcpy(ARPReply_EthHdr->ether_shost, arrivalInterface->addr, ETHER_ADDR_LEN);

        sr_send_packet(sr, ARPReplyPacket, len1, arrivalInterface->name); /* arivval interface->name */
        currPacket = currPacket->next;
        printf("%s\n", "ARP Reply sent.");
        free(ARPReplyPacket);

      }

      sr_arpreq_destroy(& sr->cache, cacheReq);
    }


}

void ARPHandlerFunc(struct sr_instance* sr, uint8_t * packet, unsigned int len, char* interface)
{
      sr_arp_hdr_t * arpHead = (sr_arp_hdr_t *) (packet + sizeof(sr_ethernet_hdr_t)); /* Move pointer to arp header start */
      struct sr_if * arrivalInterface = sr_get_interface(sr, interface);

      if (arpHead->ar_tip != arrivalInterface->ip) /* Check if target IP is equal to interface of router through which it arrived.*/
      {
        printf("%s\n", "ARP packet was not destined to router." );
        return;
      }
      else /* Destined to router. */
      {
          if (ntohs(arpHead->ar_op) == arp_op_request) /* It was an ARP Request. */
          {
              printf("%s\n", "ARP request received.");
              ARPReqHandler(sr, packet, len, arrivalInterface, arpHead);
          } 
          else if (ntohs(arpHead->ar_op) == arp_op_reply) /* It was an ARP reply */
          {
            printf("%s\n", "Got an ARP Reply" );
            ARPReplyHandler(sr, packet, len, arrivalInterface, arpHead);
           
          }
          else
          {
            printf("%s\n", "Jaani wtf ye konsa ARP hai" );
            return;
          }
      }
    
}


void sr_handlepacket(struct sr_instance* sr,
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
  /* REQUIRES */
  assert(sr);
  assert(packet);
  assert(interface);

  printf("*** -> Received packet of length %d \n",len);

  /* fill in code here */

  uint16_t packetType = ethertype(packet);

  int minlength = sizeof(sr_ethernet_hdr_t);

  /* Check if packet is of ARP or IP. Also check length.*/
  if (len >= minlength)
  {
    printf("%s\n", "Length is ok." );
    if (packetType == ethertype_arp)
    {
      printf("%s\n", "This was an ARP packet." );
      ARPHandlerFunc(sr, packet, len, interface);
    }
    else if (packetType == ethertype_ip)
    {
      printf("%s\n", "This was an IP packet." );
      IPHandlerFunc(sr, packet, len, interface);
    }
    else
    {
      printf("%s\n", "lol hogya." );
    }
  }
  else
  {
    printf("%s\n", "Size of packet is not ok." );
  }

}/* end sr_ForwardPacket */

