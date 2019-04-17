/**
 * filename: beat.c
 * description: main function of the beat program
 * author : rovo98
 */

#include "config.h"
#include "funcs.h"
#include "authalgs.h"
#include <pcap.h>
#include <time.h>
#include <string.h>

/**
 * @brief the main function of the beat program
 */
int main(int argc, char* argv[])
{
    if (check_running() <= 0)
        return 0;
    if (dealOption(argc, argv) == FALSE)
        return -1;
    /** signal(SIGALRM, sig_handle); // 定时器  */
    /** signal(SIGHUP, sig_handle);  // 注销时  */
    /** signal(SIGINT, sig_handle);  // Ctrl+C  */
    /** signal(SIGQUIT, sig_handle); // Ctrl+\  */
    /** signal(SIGTSTP, sig_handle); // Ctrl+Z  */
    /** signal(SIGTERM, sig_handle); // 被结束时  */
    fprintf(stdout, "This program is designed by dcLunatic and modified by rovo98(To make network connecting progress automatically!😸)\n\n");

    pcap_t* handle = NULL;
    char* device = NULL;
    bpf_u_int32 net, mask;
    device = pcap_lookupdev(errbuf);
    if (device == NULL) {
        err(-2);
    }
    strcpy(device, interface);
    if (pcap_lookupnet(device, &net, &mask, errbuf) == -1) {
        err(-2);
    }
    handle = pcap_open_live(device, 65535, 1, 1024, errbuf);
    if (handle == NULL)
        err(-2);

    gHandle = handle;
    fprintf(stdout, ">> Waiting for the Certification of 'Ruijie'...\n");
    if (bIsAuto) {
        if ((pcap_loop(handle, -1, pcap_handle, (u_char*)handle)) == -1)
            err(-2);
    } else {
        fprintf(stdout, "Using existed echoKey:0x%x echoNo:0x%x\n", echoKey, echoNo);
        bCapture = TRUE;
        bIsStart = TRUE;
    }
    if (bIsDebug)
        fprintf(stdout, "\b\bechoInterval = %d\n", echoInterval);
    if (bIsUpdateMac)
        setFackMac(interface);
    fprintf(stdout, "\b\b>> Before running, the 'Ruijie' already sended %d echoPackets!\n", echoNo);
    if (bIsBackground) {
        fprintf(stdout, "\n>> Program runs in the background!\n");
        fprintf(stdout, ">> Log infomation stored in %s.\n", logFile);
        init_daemon();
        time_t now;
        FILE* file = fopen(logFile, "a+");
        time(&now);
        if (lock()) {
            fprintf(file, ">> %s: Lock File ERROR, Quit program!\n", ctime(&now));
            fclose(file);
            return -1;
        }

        time(&now);
        fprintf(file, "\n\n-------------------------------------------------------\n");
        fprintf(file, "%sRunning ruijie-beat program\nfileName: %s\n", ctime(&now), argv[0]);
        fprintf(file, "\t  interface: %s\n\t  echointerval: %d\n\t  updatemac: %d\n\t  bIsAuto: %d\n**echoKey: 0x%x**\n", interface, echoInterval, bIsUpdateMac, bIsAuto, echoKey);
        fprintf(file, "Before running, the ruijie already sended %d echoPackets.\n", echoNo);

        if (bIsDebug) {
            fprintf(file, "\n\nSuccess Packet Content\n");
            fprint_packet_content(successPacket, 448);
        }
        fclose(file);
        while (1) {

            file = fopen("/var/log/ruijie-beat.log", "a+");
            if (file) {
                time(&now);
                fprintf(file, "%s\t\t\tsend the No.%d echoPacket.\n", ctime(&now), echoNo + 1);
                fclose(file);
            }
            sendEchoPacket();
            sleep(echoInterval);
        }

    } else {
        // To make the program to continue sending echoPackets
        while (1) {
            sendEchoPacket();
            time_t now;
            if (sendCount % 10 == 0) {
                time(&now);
                fprintf(stdout, "%sThe ruijie program has already sent.%d echoPackets\n\n", ctime(&now), echoNo);
            }
            sleep(echoInterval);
        }
    }
    return 0;
}
