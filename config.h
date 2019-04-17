/**
 *
 * filename: config.h
 * description: configurations for beat program
 * author : rovo98
 */
#ifndef BEAT_CONFIG_H
#define BEAT_CONFIG_H

#include "types.h"
#include <fcntl.h>
#include <getopt.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stdint.h>
#include <stdio.h>

#define LOCKMODE (S_IRWXU | S_IRWXG | S_IRWXO) //锁文件掩码

static const char lockFile[] = "/var/run/ruijie-beat.lock"; //lock file
static const char logFile[] = "/var/log/ruijie-beat.log";   //log file for program to run in the background
int lockfd;                                                 // lock file value
struct flock fl;
static u_int32_t echoKey = 0, echoNo = 0; //special param for echoPacket
static u_char* successPacket;
static u_char sendPacket[0x2D];
u_char localMAC[6], destMAC[6], orignMAC[6];
static u_int32_t sendCount = 0;
static char* interface = NULL;        //specified network interface
static boolean bIsHelp = FALSE;       //flag for printing help infos
static boolean bIsStart = FALSE;      //flag: whether beat is already start to send echoPacket
static boolean bCapture = FALSE;      //flag: whether beat program has captrued the successPacket
static boolean bIsBackground = FALSE; //flag: whether beat program running in the background
static boolean bIsDebug = FALSE;      //flag: whether printing debug infos
static boolean bIsUpdateMac = FALSE;  //flag: to modify mac address or not
static boolean bIsAuto = TRUE;        //flag: Get echoKey echoNo automatically or not
static int echoInterval = 30;         //interval to send echoPacket

/*long option*/
static const struct option long_options[] = {
    { "interface", 1, 0, 'i' },
    { "help", 0, 0, 'h' },
    { "windows", 0, 0, 'w' },
    { "background", 0, 0, 'b' },
    { "echointerval", 1, 0, 'e' },
    { "updatemac", 0, 0, 'u' },
    { "debug", 0, 0, 'd' },
    { "echokey", 1, 0, 'k' },
    { "echono", 1, 0, 'n' },
    { "remotemac", 1, 0, 'r' },
    { "sourcemac", 1, 0, 's' }
};
/*short option*/
static const char* short_options = "i:e:hwbudk:n:r:s:";

#endif
