/**
 *
 * filename: authalgs.c
 * description: Implementation of the functions defined in authalgs.h and misc
 * author : rovo98
 */

#include "config.h"
#include "authalgs.h"
#include <arpa/inet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

/* ################################################
 *
 * Implementation of the functions
 *
 *#################################################*/

/**
 * @brief Resolving the Echokey from the success packet
 * @param *capBuf the buffer captured packet
 */
void getEchoKey(const u_char* capBuf)
{
    if (bIsDebug) {
        if (!bIsBackground) {
            fprintf(stdout, "Success Packet Content\n");
            print_packet_content(capBuf, 448);
        } else {
            successPacket = (u_char*)malloc(448);
            for (int i = 0; i < 448; i++)
                successPacket[i] = capBuf[i];
        }
    }
    int i, offset = 0x1c + capBuf[0x1b] + 0x69 + 24; /* 通过比较了大量抓包，通用的提取点就是这样的 */
    u_char* base = (u_char*)(&echoKey);
    for (i = 0; i < 4; i++)
        base[i] = encode(capBuf[offset + i]);
    echoKey = ntohl(echoKey);
    echoKey += 0x102b;
    if (bIsDebug)
        fprintf(stdout, "\b\bEcho Key = 0x%x\n", echoKey);
}
/**
 * @brief To construct an echoPacket.
 * @param echoBuf the echoPacket to be filled.
 */
void fillEchoPacket(u_char* echoBuf)
{
    int i;
    u_int32_t dd1 = htonl(echoKey + echoNo), dd2 = htonl(echoNo);
    u_char *bt1 = (u_char*)&dd1, *bt2 = (u_char*)&dd2;
    echoNo++;
    for (i = 0; i < 4; i++) {
        echoBuf[0x18 + i] = encode(bt1[i]);
        echoBuf[0x22 + i] = encode(bt2[i]);
    }
    echoBuf[0x22 + 2] = encode(bt2[2] + 0x10);
    echoBuf[0x22 + 3] = encode(bt2[3] + 0x2b);
}
/**
 * @brief Fill the Ethernet frame
 * @param protocol
 */
void fillEtherAddr(u_int32_t protocol)
{
    /* 填充MAC地址和协议 */
    memset(sendPacket, 0, 0x2D);
    memcpy(sendPacket, destMAC, 6);
    memcpy(sendPacket + 0x06, localMAC, 6);
    *(u_int32_t*)(sendPacket + 0x0C) = htonl(protocol);
}
/**
 * @brief sending the echoPackets
 */
int sendEchoPacket()
{
    if (sendCount++ == 0) {
        u_char echo[] = {
            0x00, 0x1E, 0xFF, 0xFF, 0x37, 0x77, 0x7F, 0x9F, 0xFF, 0xFF, 0xD9, 0x13, 0xFF, 0xFF, 0x37, 0x77,
            0x7F, 0x9F, 0xFF, 0xFF, 0xF7, 0x2B, 0xFF, 0xFF, 0x37, 0x77, 0x7F, 0x3F, 0xFF
        };
        fprintf(stdout, ">> Sending echoPackets to keep online...\n");
        fillEtherAddr(0x888E01BF);
        memcpy(sendPacket + 0x10, echo, sizeof(echo));
    }
    fillEchoPacket(sendPacket);
    if (bIsDebug) {
        if (!bIsBackground) {
            printf("No.%d\n", echoNo);
            print_packet_content(sendPacket, 0x2D);
        } else {
            fprint_packet_content(sendPacket, 0x2D);
        }
    }

    return pcap_sendpacket(gHandle, sendPacket, 0x2D);
}

/**
 * @brief print out the packet content
 * @param packet the packet to be print
 * @param packet_len the length of the packet
 */
void print_packet_content(const u_char* packet, int packet_len)
{
    int i;
    for (i = 0; i < packet_len / 16; i++) {
        printf("%04x:   ", i * 16);
        for (int j = 0; j < 16; j++)
            printf("%02x ", packet[i * 16 + j]);
        printf("\t");
        for (int k = 0; k < 16; k++)
            if (isprint(packet[16 * i + k]))
                printf("%c ", packet[16 * i + k]);
            else
                printf(". ");
        printf("\n");
    }
    printf("%04x:   ", i * 16);
    int l = i * 16;
    for (; l < packet_len; l++)
        printf("%02x ", packet[l]);
    l = i * 16;
    for (int j = 0; j < (i + 1) * 16 - packet_len; j++)
        printf("   ");
    printf("\t");
    for (; l < packet_len; l++)
        if (isprint(packet[l]))
            printf("%c ", packet[l]);
        else
            printf(". ");
    printf("\n\n\n");
}
/**
 * @brief print out the packet content to a log file.
 * @param packet the packet to be printed.
 * @param packet_len the length of the packet
 */
void fprint_packet_content(const u_char* packet, int packet_len)
{
    int i;
    FILE* file = fopen(logFile, "a+");
    for (i = 0; i < packet_len / 16; i++) {
        fprintf(file, "%04x:   ", i * 16);
        for (int j = 0; j < 16; j++)
            fprintf(file, "%02x ", packet[i * 16 + j]);
        fprintf(file, "\t");
        for (int k = 0; k < 16; k++)
            if (isprint(packet[16 * i + k]))
                fprintf(file, "%c ", packet[16 * i + k]);
            else
                fprintf(file, ". ");
        fprintf(file, "\n");
    }
    fprintf(file, "%04x:   ", i * 16);
    int l = i * 16;
    for (; l < packet_len; l++)
        fprintf(file, "%02x ", packet[l]);
    l = i * 16;
    for (int j = 0; j < (i + 1) * 16 - packet_len; j++)
        fprintf(file, "   ");
    fprintf(file, "\t");
    for (; l < packet_len; l++)
        if (isprint(packet[l]))
            fprintf(file, "%c ", packet[l]);
        else
            fprintf(file, ". ");
    fprintf(file, "\n\n\n");
    fclose(file);
}
/**
 * @brief print out the mac address
 */
void printMAC(uint8_t* mac)
{
    for (int i = 0; i < 6; i++) {
        fprintf(stdout, "%02x", mac[i]);
        if (i != 5)
            fprintf(stdout, ":");
    }
    fprintf(stdout, "(");
    for (int i = 0; i < 6; i++) {
        fprintf(stdout, "%02x", mac[i]);
    }
    fprintf(stdout, ")");
}
/**
 * @brief print out the packet conent of the specified packet
 * @param packet the packet to be printed
 * @param packet_len the length of the packet.
 */
/**
 * @brief set the specified mac address
 * @param dev the network interface
 */
void setFackMac(char* dev)
{
    macAddrGet((uint8_t*)orignMAC, dev);
    fprintf(stdout, "\n\n>> Reset the mac of device %s :  ", dev);
    for (int i = 0; i < 6; i++) {
        fprintf(stdout, "%02x", localMAC[i]);
        if (i != 5)
            fprintf(stdout, ":");
    }
    fprintf(stdout, "  , then restart it.\n");
    pcap_close(gHandle);
    macAddrSet((uint8_t*)localMAC, dev);
    if_updown(dev, DOWN);
    if_updown(dev, UP);
    fprintf(stdout, ">> Reset MAC done!\n");
    fprintf(stdout, ">> Reopen the device: %s \n", dev);
    gHandle = pcap_open_live(dev, 65535, 1, 1024, errbuf);
    if (gHandle == NULL)
        err(-2);
    fprintf(stdout, ">> Open sucessfully!\n");
}
/**
 * @brief get the mac address from the specified network interface.
 * @param mac the mac address 
 * @param dev network interface
 */
int macAddrSet(uint8_t* mac, char* dev)
{
    struct ifreq temp;
    struct sockaddr* addr;

    int fd = 0;
    int ret = -1;

    if ((0 != getuid()) && (0 != geteuid()))
        return -1;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    strcpy(temp.ifr_name, dev);
    addr = (struct sockaddr*)&temp.ifr_hwaddr;

    addr->sa_family = ARPHRD_ETHER;
    memcpy(addr->sa_data, mac, 6);

    ret = ioctl(fd, SIOCSIFHWADDR, &temp);

    close(fd);
    return ret;
}
/**
 * @brief set the mac address for the specified network interface.
 * @param mac the mac address
 * @param dev network interface
 */
int macAddrGet(uint8_t* mac, char* dev)
{
    struct ifreq temp;
    struct sockaddr* addr;

    int fd = 0;
    int ret = -1;

    if ((0 != getuid()) && (0 != geteuid()))
        return -1;

    if ((fd = socket(AF_INET, SOCK_DGRAM, 0)) < 0) {
        return -1;
    }

    strcpy(temp.ifr_name, dev);
    addr = (struct sockaddr*)&temp.ifr_hwaddr;

    addr->sa_family = ARPHRD_ETHER;

    ret = ioctl(fd, SIOCGIFHWADDR, &temp);
    close(fd);

    if (ret < 0)
        return -1;

    memcpy(mac, addr->sa_data, 6);

    return ret;
}

/**
 * @brief reverse the 8 bits of the given char
 * @param base  the char to be operated.
 * @return the reversed char.
 */
u_char encode(u_char base)
{
    u_char result = 0;
    int i;
    for (i = 0; i < 8; i++) {
        result <<= 1;
        result |= base & 0x01;
        base >>= 1;
    }
    return ~result;
}
/**
 * @brief callback function for the pcap_loop()
 */
void pcap_handle(u_char* user, const struct pcap_pkthdr* h, const u_char* buf)
{
    if (buf[0x0c] == 0x88 && buf[0x0d] == 0x8e) {
        if (buf[0x0F] == 0x00 && buf[0x12] == 0x03) { /* 认证成功 */
            echoNo = 0;
            fprintf(stdout, ">> Capture certification of ruijie successfully!\n");
            for (int i = 0; i < 6; i++) {
                localMAC[i] = buf[i];
                destMAC[i] = buf[i + 6];
            }
            bCapture = TRUE;
            getEchoKey(buf);
        }
        if (buf[0x10] == 0 && buf[0x11] == 0x1e && buf[0x12] == 0xff && buf[0x13] == 0xff && buf[0x2c] == 0xff) {
            //随便简单判断一下是否是心跳包
            echoNo++;
            //printf("心跳包:%d\n", echoNo);
            // modified by rovo98, break the loop of catch packets when
            // we successfully catch two echoPackets
            if (echoNo > 1) {
                fprintf(stdout, "Break the loop of catching echoPackets!\n");
                bIsStart = TRUE;
                pcap_breakloop(gHandle);
            }
        }
    }
}
/**
 * @brief turn on/off the specified network interface
 * @param ifname the interface name
 * @param flag this param stands for the on / off 
 */
int if_updown(char* ifname, int flag)
{
    int fd, rtn;
    struct ifreq ifr;

    if (!ifname) {
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, (const char*)ifname, IFNAMSIZ - 1);

    if ((rtn = ioctl(fd, SIOCGIFFLAGS, &ifr)) == 0) {
        if (flag == DOWN)
            ifr.ifr_flags &= ~IFF_UP;
        else if (flag == UP)
            ifr.ifr_flags |= IFF_UP;
    }

    if ((rtn = ioctl(fd, SIOCSIFFLAGS, &ifr)) != 0) {
        perror("SIOCSIFFLAGS");
    }

    close(fd);

    return rtn;
}
/**
 * @brief print out the error message for the pcap's operations.
 * @param ret the args for exit() function
 */
void err(int ret)
{
    fprintf(stderr, "%s\n", errbuf);
    exit(ret);
}
