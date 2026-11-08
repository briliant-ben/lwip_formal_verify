#ifndef LWIP_LWIPOPTS_H
#define LWIP_LWIPOPTS_H

#define NO_SYS                          1
#define LWIP_SOCKET                     0
#define LWIP_NETCONN                    0
#define SYS_LIGHTWEIGHT_PROT            0

#define MEM_ALIGNMENT                   8
#define MEM_SIZE                        (64 * 1024)
#define MEMP_NUM_PBUF                   64
#define PBUF_POOL_SIZE                  64

#define LWIP_ARP                        1
#define LWIP_ETHERNET                   1
#define LWIP_IPV4                       1
#define IP_REASSEMBLY                   1
#define IP_FRAG                         1
#define LWIP_ICMP                       1
#define LWIP_IGMP                       1
#define LWIP_RAW                        1
#define LWIP_DHCP                       1
#define LWIP_AUTOIP                     1
#define LWIP_ACD                        1
#define LWIP_UDP                        1
#define LWIP_TCP                        1
#define LWIP_DNS                        1

#define LWIP_IPV6                       1
#define LWIP_IPV6_REASS                 1
#define LWIP_IPV6_FRAG                  1
#define LWIP_ICMP6                      1
#define LWIP_IPV6_MLD                   1
#define LWIP_IPV6_DHCP6                 1
#define LWIP_IPV6_DHCP6_STATELESS       1
#define LWIP_DHCP6_GET_NTP_SRV          1
#define LWIP_ND6_RDNSS_MAX_DNS_SERVERS  2

#define LWIP_6LOWPAN                    1
#define LWIP_6LOWPAN_INFER_SHORT_ADDRESS 1
#define LWIP_ZEPIF                      1

#define SLIP_RX_FROM_ISR                1
#define SLIP_RX_QUEUE                   1

#define PPP_SUPPORT                     1
#define PPPOE_SUPPORT                   1
#define PPPOE_TERM_UNKNOWN_SESSIONS     1
#define PPPOL2TP_SUPPORT                1
#define VJ_SUPPORT                      1
#define LWIP_INCLUDED_POLARSSL_MD5      1

#define LWIP_MDNS_RESPONDER             1
#define LWIP_NUM_NETIF_CLIENT_DATA      4
#define LWIP_SNMP                       1
#define MIB2_STATS                      1

#endif /* LWIP_LWIPOPTS_H */
