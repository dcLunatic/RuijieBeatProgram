#include "funcs.h"
#include "config.h"
#include <signal.h>
#include <unistd.h>
#include <stdlib.h>

/************************************************
 *      Implementation of funcitions            *
 ************************************************/

/**
 * @brief Initialize the beat program and running as a background daemon.
 * @return SUCCESS if operation done successfully;
 *          otherwise FAIL.
 */
status init_daemon()
{
    int pid;

    //忽略终端I/O信号，STOP信号
    signal(SIGTTOU, SIG_IGN);
    signal(SIGTTIN, SIG_IGN);
    signal(SIGTSTP, SIG_IGN);
    signal(SIGHUP, SIG_IGN);

    pid = fork();
    if (pid > 0) {
        exit(0); //结束父进程，使得子进程成为后台进程
    } else if (pid < 0) {
        return FAIL;
    }
    //建立一个新的进程组,在这个新的进程组中,子进程成为这个进程组的首进程,以使该进程脱离所有终端
    setsid();

    //再次新建一个子进程，退出父进程，保证该进程不是进程组长，同时让该进程无法再打开一个新的终端
    pid = fork();
    if (pid > 0) {
        exit(0);
    } else if (pid < 0) {
        return FAIL;
    }
    //关闭所有从父进程继承的不再需要的文件描述符
    //for(i=0;i< NOFILE;close(i++));

    //改变工作目录，使得进程不与任何文件系统联系
    chdir("/");

    //将文件当时创建屏蔽字设置为0
    umask(0);

    //忽略SIGCHLD信号
    signal(SIGCHLD, SIG_IGN);

    return SUCCESS;
}

/**
 * @brief returns TRUE if the beat program is already running;
 *         FALSE otherwise.
 */
boolean check_running()
{
    lockfd = open(lockFile, O_RDWR | O_CREAT, LOCKMODE);
    if (lockfd < 0) {
        fprintf(stderr, ">> !! Fail to open the lock file.");
        return TRUE;
    }
    fl.l_start = 0;
    fl.l_whence = SEEK_SET;
    fl.l_len = 0;
    fl.l_type = F_WRLCK;
    if (fcntl(lockfd, F_GETLK, &fl) < 0) {
        fprintf(stderr, ">> !! lock file: no such file or directory!");
        return TRUE;
    }
    if (fl.l_type != F_UNLCK) {
        fprintf(stdout, ">> beat program is already running!-> to terminate it.\n");
        fprintf(stdout, ">> kill process with (PID=%d).\n", fl.l_pid);
        if (kill(fl.l_pid, SIGINT) == -1) {
            fprintf(stderr, ">> fail to terminate the process!\n");
        } else {
            fprintf(stdout, ">> terminate the process successfully!\n");
        }
        return TRUE;
    }
    return FALSE;
}

/**
 * @brief To lock the lock file for the beat program.
 * @return status(success) if done the operation successfully;
 *          otherwise status(fail)
 */
status lock()
{
    fl.l_type = 1;
    fl.l_pid = getpid();
    int result = fcntl(lockfd, F_SETLKW, &fl);
    if (result < 0) {
        return FAIL;
    }
    return SUCCESS;
}
/**
 * @brief print out the help information about the beat program 
 */
void printHelpInfo()
{
    fprintf(stdout, "=================================================================================================================\n");
    fprintf(stdout, "==                                 BEAT conneting to the world                                                 ==\n");
    fprintf(stdout, "==              This beat program is mainly designed by dcLunatic and modified by rovo98!                      ==");
    fprintf(stdout, "=================================================================================================================\n");
    fprintf(stdout, "=+If this program is already running as a background deamon, then this will quit when you re-run this program! +=");
    fprintf(stdout, "------------------------------------------Usage----------------------------------------------------\n\n");
    fprintf(stdout, "-i\t--interface\t\tSpecify the network interface to connect the network\n");
    fprintf(stdout, "-e\t--echointerval\t\tThe time interval to send echoPacket(second, s)(default: 30s)\n");
    fprintf(stdout, "-b\t--background\t\tRun this program as a background daemon successfully\n");
    fprintf(stdout, "-u\t--updatemac\t\tUpdate the mac address of the specified network interface(Warning: this operation will restart the interface)\n");
    fprintf(stdout, "-d\t--debug\t\t\tRun in the debug mode\n");
    fprintf(stdout, "-h\t--help\t\t\tshow help information about this program\n");
    fprintf(stdout, "\n\nIf neccessary, you can specify this following four parameters yourself rather than computing by this program\n");
    fprintf(stdout, "(To make the echoPacket sending progress more quickly, this will ignore capturing the packet from your virtual machine!)");
        fprintf(stdout, "-k\t--echokey\n");
    fprintf(stdout, "-n\t--echono\n");
    fprintf(stdout, "-r\t--remotemac\n");
    fprintf(stdout, "-s\t--sourcemac\n");
    fprintf(stdout, "\n-----------------------------------------NOTICES----------------------------------------\n\n");
    fprintf(stdout, "该程序自行计算提供的echokey似乎有一两位有问题，所以当发送256个包之后会断开连接\n所以这里建议把心跳包间隔调大一点，广金的大概是6分钟检测一次把目前\n\n");
    fprintf(stdout, "    echointerval(s)    activetime\n");
    fprintf(stdout, "    30                 128m\n");
    fprintf(stdout, "    60                 256m\n");
    fprintf(stdout, "    113                8h\n");
    fprintf(stdout, "    256                18.2h\n");
    fprintf(stdout, "    300                21.3h\n\n\n");
}
/**
 * @brief a navie implementation of deal with the command-line arguments
 */
boolean dealOption(int argc, char* argv[])
{
    opterr = 0;
    int c;
    int time = -1;
    uint64_t remoteMac = 0, sourceMac = 0;
    while ((c = getopt_long(argc, argv, short_options, long_options, 0)) != -1) {
        switch (c) {
        case 'h':
            bIsHelp = TRUE;
            break;
        case 'i':
            interface = optarg;
            break;
        case 'b':
            bIsBackground = TRUE;
            break;
        case 'e':
            time = atoi(optarg);
            break;
        case 'u':
            bIsUpdateMac = TRUE;
            break;
        case 'd':
            bIsDebug = TRUE;
            break;
        case 'k':
            echoKey = atoi(optarg);
            break;
        case 'n':
            echoNo = atoi(optarg);
            break;
        case 'r':
            remoteMac = htoi(optarg);
            break;
        case 's':
            sourceMac = htoi(optarg);
            break;
        case '?':
            if (optopt == 'i') {
                fprintf(stderr, "Error: option %c must have an argument\n\n", optopt);
                printHelpInfo();
            } else {
                fprintf(stderr, "Error: unknown option %c\n\n", optopt);
                printHelpInfo();
            }
            return FALSE;
        }
    }
    if (echoKey > 0 && echoNo > 0 && remoteMac > 0 && sourceMac > 0) {
        bIsAuto = FALSE;
        for (int i = 5; i >= 0; i--) {
            destMAC[i] = remoteMac % 256;
            localMAC[i] = sourceMac % 256;
            remoteMac /= 256;
            sourceMac /= 256;
        }
    } else if (!echoKey && !echoNo && !remoteMac && !sourceMac) {
        ; // do nothing
    } else {
        fprintf(stderr, "you must specified remoteMac, sourceMac, echoKey, echoNo at one time.\n\n");
        printHelpInfo();
        return FALSE;
    }
    if (time > 0)
        echoInterval = time;
    if (bIsHelp) {
        printHelpInfo();
        exit(0);
    }
    if (interface == NULL) {
        fprintf(stderr, "Error: must specified a device\n\n");
        printHelpInfo();
        return FALSE;
    }
    return TRUE;
}
/**
 * @brief converts a hex string to int value
 * @param s[] a hex string to be converted
 * @return int value of the hex string
 */
u_int64_t htoi(char s[])
{
    int i;
    uint64_t n = 0;
    if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
        i = 2;
    } else {
        i = 0;
    }
    for (; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'z') || (s[i] >= 'A' && s[i] <= 'Z'); ++i) {
        if (tolower(s[i]) > '9') {
            n = 16 * n + (10 + tolower(s[i]) - 'a');
        } else {
            n = 16 * n + (tolower(s[i]) - '0');
        }
    }
    return n;
}
