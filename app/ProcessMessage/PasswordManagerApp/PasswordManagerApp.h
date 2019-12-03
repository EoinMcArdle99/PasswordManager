#pragma once
#include "pch.h"
#include "SharedData.h"
#include "../ProcessMessage/Encryption.h"
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <string>
#include <iostream>
#include <Windows.h>

#define MAXCHARS 200
#define RUNMODE "/r"
#define ADDACCOUNT "/a"

char * allocateMemory(char *data, account *addAccount, int *dataIndex);
int updateDatabase(account addAccount);
void readFile();
void addAccount();
void runBackground();
int appendData(char *buff, char **dataStream, char *delim, int stringLength);