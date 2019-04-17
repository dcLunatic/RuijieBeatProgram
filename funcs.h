/**
 * filename: funcs.h
 * description: tool functions for the beat program
 * author rovo98
 *
 */

#ifndef funcs_h
#define funcs_h
#include "types.h"
#include <sys/types.h>

int init_daemon();                          // initialize the beat program and running in the background
boolean check_running();                    // check if the beat program is already running or not
status lock();                              // to lock the 'lock' file for the beat program
void printHelpInfo();                       // print out the help information of this program
boolean dealOption(int argc, char* argv[]); // deal with the command-line arguments.
u_int64_t htoi(char s[]);                                                              // converts hex string to int value.

#endif
