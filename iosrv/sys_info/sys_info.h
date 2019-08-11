#pragma once
#include <iostream>
#include <fstream>
#include <stdio.h>
#include <stdlib.h>
#include <Windows.h>
#include <time.h>
#include <aclapi.h>
#include <string>
#include <assert.h>
#include <VersionHelpers.h>

namespace sys_info
{
	// take os version
	char* take_os_version(); // call this
	char* take_os_vers();

	void getSysTimeStr(char*& str);
	void TickCount(int&);
	void sysMemoryStatus(char*& statRes);
	void localDisksStat(char*&);

	// access info
	void accessInfo(char* path);
	void print_rights(ACCESS_MASK p);
}