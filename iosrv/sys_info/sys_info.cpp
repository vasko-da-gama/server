#pragma warning(disable : 4996)
#include "sys_info.h"
using namespace std;

namespace sys_info
{
	char* take_os_version()
	{
		char* win_ver = (char*)malloc(sizeof(char) * 15);
		if (IsWindows8Point1OrGreater())
		{
			sprintf(win_ver, "Windows 8.1");
			return win_ver;
		}
		if (IsWindows8OrGreater())
		{
			char* tmp = take_os_vers();
			if (!strcmp(tmp, "Windows 8"))
			{
				sprintf(win_ver, "Windows 8");
				return win_ver;
			}
			return tmp;
		}
		if (IsWindows7OrGreater())
		{
			sprintf(win_ver, "Windows 7");
			return win_ver;
		}
		if (IsWindowsVistaOrGreater())
		{
			sprintf(win_ver, "Windows Vista");
			return win_ver;
		}
		if (IsWindowsXPOrGreater())
		{
			sprintf(win_ver, "Windows XP");
			return win_ver;
		}
		sprintf(win_ver, "Unknow");
		return win_ver;
	}

	void getOsVersionStr(char*& osv)
	{
		if (IsWindows10OrGreater())
		{
			osv = (char*)malloc(sizeof(char) * strlen("Windows 10"));
			memcpy(osv, "Windows 10", sizeof(char) * strlen("Windows 10"));
			return;
		}

		OSVERSIONINFOEX osvi;
		ZeroMemory(&osvi, sizeof(OSVERSIONINFOEX));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);
		GetVersionEx((LPOSVERSIONINFOA)& osvi);

		if (osvi.dwMajorVersion == 4)
		{
			if (osvi.dwMinorVersion == 0)
			{
				osv = (char*)malloc(sizeof(char) * strlen("Windows 95"));
				memcpy(osv, "Windows 95", sizeof(char) * strlen("Windows 95"));
				osv[strlen("Windows 95")] = '\0';
				return;
			}
			if (osvi.dwMinorVersion == 10)
			{
				osv = (char*)malloc(sizeof(char) * strlen("Windows 95"));
				memcpy(osv, "Windows 98", sizeof(char) * strlen("Windows 95"));
				osv[strlen("Windows 95")] = '\0';
				return;
			}
			if (osvi.dwMinorVersion == 90)
			{
				osv = (char*)malloc(sizeof(char) * strlen("WindowsME"));
				memcpy(osv, "WindowsME", sizeof(char) * strlen("WindowsME"));
				osv[strlen("WindowsME")] = '\0';
				return;
			}
		}
		if (osvi.dwMajorVersion == 5)
		{
			if (osvi.dwMinorVersion == 0)
			{
				osv = (char*)malloc(sizeof(char) * strlen("Windows 2000"));
				memcpy(osv, "Windows 2000", sizeof(char) * strlen("Windows 2000"));
				osv[strlen("Windows 2000")] = '\0';
				return;
			}
			if (osvi.dwMinorVersion == 1)
			{
				osv = (char*)malloc(sizeof(char) * strlen("Windows 95"));
				memcpy(osv, "Windows XP", sizeof(char) * strlen("Windows 95"));
				osv[strlen("Windows XP")] = '\0';
				return;
			}
			if (osvi.dwMinorVersion == 2)
			{
				osv = (char*)malloc(sizeof(char) * strlen("Windows 2003"));
				memcpy(osv, "Windows 2003", sizeof(char) * strlen("Windows 2003"));
				osv[strlen("Windows 2003")] = '\0';
				return;
			}
		}
		if (osvi.dwMajorVersion == 6)
		{
			if (osvi.dwMinorVersion == 0)
			{
				osv = (char*)malloc(sizeof(char) * strlen("Windows Vista"));
				memcpy(osv, "Windows Vista", sizeof(char) * strlen("Windows Vista"));
				osv[strlen("Windows vista")] = '\0';
				return;
			}
			if (osvi.dwMinorVersion == 1)
			{
				osv = (char*)malloc(sizeof(char) * strlen("Windows 7"));
				memcpy(osv, "Windows 7", sizeof(char) * strlen("Windows 7"));
				osv[strlen("Windows 8")] = '\0';
				return;
			}
			if (osvi.dwMinorVersion == 2)
			{
				osv = (char*)malloc(sizeof(char) * strlen("Windows 8"));
				memcpy(osv, "Windows 8", sizeof(char) * strlen("Windows 8"));
				osv[strlen("Windows 8")] = '\0';
				return;
			}
			if (osvi.dwMinorVersion == 3)
			{
				osv = (char*)malloc(sizeof(char) * strlen("Windows 8.1"));
				memcpy(osv, "Windows 8.1", sizeof(char) * strlen("Windows 8.1"));
				osv[strlen("Windows 8.1")] = '\0';
				return;
			}
		}
	}

	char* take_os_vers()
	{
		int sum_Mver;
		char* buf = new char[15];

		OSVERSIONINFOEX osvi;
		ZeroMemory(&osvi, sizeof(OSVERSIONINFO));
		osvi.dwOSVersionInfoSize = sizeof(OSVERSIONINFO);

		DWORDLONG const dwlConditionMask = VerSetConditionMask(VerSetConditionMask(VerSetConditionMask(0, VER_MAJORVERSION, VER_GREATER_EQUAL), VER_MINORVERSION, VER_GREATER_EQUAL), VER_SERVICEPACKMAJOR, VER_GREATER_EQUAL);
		VerifyVersionInfoW((LPOSVERSIONINFOEXW)& osvi, VER_MAJORVERSION | VER_MINORVERSION | VER_SERVICEPACKMAJOR, dwlConditionMask);

		sum_Mver = (osvi.dwMajorVersion * 100) + osvi.dwMinorVersion;
		switch (sum_Mver)
		{
		case 400:
			sprintf(buf, "%s", "Windows 95");
			break;
		case 410:
			sprintf(buf, "%s", "Windows 98");
			break;
		case 490:
			sprintf(buf, "%s", "Windows ME");
			break;
		case 500:
			sprintf(buf, "%s", "Windows 2000");
			break;
		case 501:
			sprintf(buf, "%s", "Windows XP");
			break;
		case 502:
			sprintf(buf, "%s", "Windows 2003");
			break;
		case 600:
			sprintf(buf, "%s", "Windows Vista");
			break;
		case 601:
			sprintf(buf, "%s", "Windows 7");
			break;
		case 602:
			sprintf(buf, "%s", "Windows 8");
			break;
		case 603:
			sprintf(buf, "%s", "Windows 8.1");
			break;
		default:
			char* tmp_version;
			getOsVersionStr(tmp_version);
			sprintf(buf, "%s", "Windows 10");
			break;
		}

		return buf;
	}

	void accessInfo(char* path)
	{
		cout << "\nAccess to \'" << path << "\'\n";
		PACL a;
		PSID ppsidOwner, ppsidGroup;
		PACL ppDacl, ppSacl;
		PSECURITY_DESCRIPTOR pSD;

		DWORD dwres = 0;

		dwres = GetNamedSecurityInfo(path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
			&ppsidOwner, &ppsidGroup, &ppDacl, &ppSacl, &pSD);

		ACL_SIZE_INFORMATION pAclInformation;
		GetAclInformation(ppDacl, &pAclInformation, sizeof(ACL_SIZE_INFORMATION), AclSizeInformation);

		PACCESS_ALLOWED_ACE pAce;
		TCHAR szAccountName[256];
		for (int i = 0; i < pAclInformation.AceCount; i++)
		{
			GetAce(ppDacl, i, (LPVOID*)& pAce);
			TCHAR szDomainName[256];
			DWORD dwSizeDomain = sizeof(szDomainName) / sizeof(TCHAR);
			SID_NAME_USE sidName;
			DWORD lpszName = sizeof(szAccountName) / sizeof(TCHAR);

			LookupAccountSid(NULL, (PSID)& pAce->SidStart, szAccountName, &lpszName, szDomainName, &dwSizeDomain, &sidName);

			//cout << szAccountName << " :: " << pAce->Mask << endl;
			printf("%s\t::\t%X\n", szAccountName, pAce->Mask);
			print_rights((ACCESS_MASK)pAce->Mask);
			printf("\n");
		}


	}

	void print_rights(ACCESS_MASK p)
	{
		cout << " RIGHTS:\n";

		// begin from bit16
		// Standard rights. Contains the object's standard access rights.
		p >>= 16;
		if (p & 0x01) cout << " | Delete access\n";                // 16
		p >>= 1;
		if (p & 0x01) cout << " | Read access\n";                  // 17
		p >>= 1;
		if (p & 0x01) cout << " | Write access to the DACL\n";     // 18
		p >>= 1;
		if (p & 0x01) cout << " | Write access to the owner\n";    // 19
		p >>= 1;
		if (p & 0x01) cout << " | Synchronize access\n";           // 20

		// other
		p >>= 4;
		if (p & 0x01) cout << " | ACCESS_SYSTEM_SECURITY\n";       // 24
		p >>= 1;
		if (p & 0x01) cout << " | MAXIMUM_ALLOWED\n";              // 25
		p >>= 1;
		if (p & 0x03) cout << " | RESERVED\n";                     // 26 - 27
		p >>= 2;
		if (p & 0x01) cout << " | GENERIC_ALL\n";                  // 28
		p >>= 1;
		if (p & 0x01) cout << " | GENERIC_EXECUTE\n";              // 29
		p >>= 1;
		if (p & 0x01) cout << " | GENERIC_WRITE\n";                // 30
		p >>= 1;
		if (p & 0x01) cout << " | GENERIC_READ\n";                 // 31
	}

	void localDisksStat(char* &ldStat)
	{
		char disks[26][4] = { 0 };
		DWORD dr = GetLogicalDrives();
		char* tmp;
		int trace = 0;

		// get available local disks
		int i = 0, count = 0;
		for (i; i < 26; i++)
		{
			if ((dr >> i) & 0x00000001)
			{
				disks[count][0] = char(65 + i);
				disks[count][1] = ':';
				disks[count][2] = '\\';
				count++;
			}
		}
		//cout << '\n' << count << " : disks found\n";
		tmp = (char*)malloc(sizeof(char) * 100); assert(tmp);
		ldStat = (char*)malloc(sizeof(char) * 100); assert(ldStat);
		memset(tmp, 0, 100);
		memset(ldStat, 0, 100);

		sprintf(ldStat, "\n%d : disks found\n", count - 1);
		trace = strlen(ldStat);

		// looking for fixed drives
		for (i = 0; i < count; i++)
		{
			if (GetDriveTypeA(disks[i]) == DRIVE_FIXED)
			{
				ULARGE_INTEGER FreeBytesAvailable, TotalNumberOfBytes, TotalNumberOfFreeBytes;
				GetDiskFreeSpaceEx(disks[i], &FreeBytesAvailable, NULL, NULL);
				sprintf(tmp, "[%s] free space: %f gb   \t| DRIVE_FIXED\n", disks[i], (float)FreeBytesAvailable.QuadPart / 1024 / 1024 / 1024);
				ldStat = (char*)realloc(ldStat, trace + strlen(tmp)); assert(ldStat);
				memcpy(ldStat + trace, tmp, strlen(tmp));
				trace += strlen(tmp);
			}

			if (GetDriveTypeA(disks[i]) == DRIVE_REMOVABLE)
			{
				ULARGE_INTEGER FreeBytesAvailable, TotalNumberOfBytes, TotalNumberOfFreeBytes;
				GetDiskFreeSpaceEx(disks[i], &FreeBytesAvailable, NULL, NULL);
				sprintf(tmp, "[%s] free space: %f gb   \t| DRIVE_REMOVABLE\n", disks[i], (float)FreeBytesAvailable.QuadPart / 1024 / 1024 / 1024);
				ldStat = (char*)realloc(ldStat, trace + strlen(tmp)); assert(ldStat);
				memcpy(ldStat + trace, tmp, strlen(tmp));
				trace += strlen(tmp);
			}
		}
		ldStat[trace] = '\0';
		free(tmp);
	}

	void TickCount(int& msec)
	{
		int hour, min, sec;
		msec = GetTickCount();
		hour = msec / (1000 * 60 * 60);
		min = msec / (1000 * 60) - hour * 60;
		sec = (msec / 1000) - (hour * 60 * 60) - min * 60;
		cout << "Working time: " << hour << ":" << min << ":" << sec << "\n";
	}

	void sysMemoryStatus(char*& statRes)
	{
		statRes = (char*)malloc(sizeof(char) * 100);
		MEMORYSTATUSEX statex;

		statex.dwLength = sizeof(statex);

		GlobalMemoryStatusEx(&statex);
		sprintf(statRes, "%d%% of global memory is loaded\nPhysical RAM: %f gb\n", statex.dwMemoryLoad, (float)statex.ullTotalPhys / (1024 * 1024 * 1024));
	}

	void getSysTimeStr(char*& str)
	{
		str = new char[80];
		struct tm* tm1;
		time_t t = time(NULL);
		t += 10800;
		//tm1 = localtime(&t);
		tm1 = gmtime(&t);
		strftime(str, 80, "%d.%m.%Y %H:%M:%S", tm1);
	}
}


