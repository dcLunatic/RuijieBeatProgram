/**
 *
 * filename: authalgs.h (authentication algorithms)
 * description: algorithms and functions for sending echoPacket of ruijie.
 * author: rovo98
 */

#ifndef AUTH_ALGS_H
#define AUTH_ALGS_H
#include "types.h"
#include <pcap.h>

#define ETHER_ADDR_LEN 6
#define UP 1
#define DOWN 0

char errbuf[PCAP_ERRBUF_SIZE]; //pcap错误缓冲区
static pcap_t* gHandle = 0;    //全局句柄

// functions declarations

void getEchoKey(const u_char* capBuf); // resolving the successPacket to get the special params
void fillEchoPacket(u_char* echoBuf);
void fillEtherAddr(u_int32_t protocol);                   // fill the ethernet frame.
int sendEchoPacket();                                     // sending the echoPacket
void print_packet_content(const u_char* packet, int packet_len); // print out the content of the packet.
void fprint_packet_content(const u_char* packet, int packet_len);
void printMAC(uint8_t* mac);                                                           // print out the mac address.
void setFackMac(char* dev);                                                            // set specified mac address
int macAddrSet(uint8_t* mac, char* dev);                                               // set mac for specified interface
int macAddrGet(uint8_t* mac, char* dev);                                               // get mac form specified interface.
u_char encode(u_char base);                                                     // reverse 8 bits
void pcap_handle(u_char* user, const struct pcap_pkthdr* h, const u_char* buf); // callball function for pcap_loop()
int if_updown(char* ifname, int flag);                                                 //turn on/off the specified interface
void err(int ret);                                                                     //error quit function
#endif
