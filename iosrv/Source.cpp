#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <iostream>
#include <Windows.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <time.h>
#include "sys_info/sys_info.h"
#include "AES/AesCrypto.h"

#pragma comment(lib, "ws2_32.lib")
using namespace std;
using namespace my_cryptoAes;

#define SOCKET_MAX_COUNT 128
#define SOCKET_MAX_VAL 65535
#define AES_KEY_BASE "hey28dbsjci239d7"

char* createInfo(); // string to send
int ctoint(char* a);

int init();
void deinit();
int sock_err(const char* func, int s);
void s_close(int s);

int aes_get_key_mask(char**);
char* aes_update_key(int);
char* encrypt_large_text(char* text, unsigned char* key, int & res_length);

void print_ip(unsigned int a);

int set_non_block_mode(int s);

int main(int argc, char* argv[])
{
	// server.exe port key_mask
	int port = 9000;
	if (argc == 2)
		port = ctoint(argv[1]);

	cout << ":: Server ::\n> Waiting...\n";
	init();
	int ls = socket(AF_INET, SOCK_STREAM, 0);

	set_non_block_mode(ls);

	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port);
	addr.sin_addr.s_addr = htonl(INADDR_ANY);

	if (bind(ls, (struct sockaddr*) & addr, sizeof(addr)) < 0)
		return sock_err("bind", ls);

	if (listen(ls, 1) < 0)
		return sock_err("listen", ls);

	int cs[SOCKET_MAX_COUNT]; // clients sockets
	memset(cs, 0, SOCKET_MAX_COUNT);

	struct pollfd pfd[SOCKET_MAX_COUNT + 1];

	for (int i = 0; i < SOCKET_MAX_COUNT; i++)
	{
		pfd[i].fd = cs[i];
		pfd[i].events = POLLIN | POLLOUT;
	}

	pfd[SOCKET_MAX_COUNT].fd = ls;
	pfd[SOCKET_MAX_COUNT].events = POLLIN;

	while (true)
	{
		int ev_cnt = WSAPoll(pfd, sizeof(pfd) / sizeof(pfd[0]), 1000);
		if (ev_cnt > 0)
		{
			for (int i = 0; i < SOCKET_MAX_COUNT; i++)
			{
				if (cs[i] == 0) continue;
				if (pfd[i].revents & POLLHUP)
				{
					// disconnect
					cout << "> Client " << cs[i] << " disconected";
					s_close(cs[i]);
					cs[i] = 0;
					pfd[i].fd = 0;
					continue;
				}
				if (pfd[i].revents & POLLERR)
				{
					cout << "> Client " << cs[i] << " disconected";
					s_close(cs[i]);
					cs[i] = 0;
					pfd[i].fd = 0;
					continue;
				}
				if (pfd[i].revents & POLLIN)
				{
					// client must request info with "get" message
					char buf[4];
					int rcv = recv(cs[i], buf, sizeof(buf), 0);
					if (rcv < 0)
						return sock_err("recv", cs[i]);
					buf[3] = '\0';

					if (strcmp("get", buf) != 0)
					{
						char answer[] = "unknown request";
						rcv = send(cs[i], (char*)answer, strlen(answer), 0);
						if (rcv < 0)
							return sock_err("send", cs[i]);
						cout << "[!] client " << cs[i] << " :: unknown request\n";
						continue;
					}

					// create info about this computer
					char* info = createInfo();

					// if we have the key mask
					char* key;
					if (argc == 3)
						key = aes_update_key(aes_get_key_mask(argv));
					else
					{
						key = (char*)malloc(16); assert(key);
						strcpy(key, AES_KEY_BASE);
					}

					// encrypt info
					int res_length = 0;
					char* encrypted = encrypt_large_text(info, (unsigned char*) key, res_length);
					rcv = send(cs[i], encrypted, res_length, 0);
					if (rcv < 0)
						return sock_err("send", cs[i]);

					cout << "> send to the " << cs[i] << " " << rcv << "bytes\n";
				}
			}

			if (pfd[SOCKET_MAX_COUNT].revents & POLLIN)
			{
				// add new client
				int addrlen = sizeof(addr);

				int i = 0;
				for (i; i < SOCKET_MAX_COUNT; i++)
					if (cs[i] == 0) {
						cs[i] = accept(ls, (struct sockaddr*) & addr, &addrlen);
						if (cs[i] < 0)
							return sock_err("accept", ls);
						pfd[i].fd = cs[i];
						pfd[i].events = POLLIN | POLLOUT;

						cout << "> Client ";
						print_ip(ntohl(addr.sin_addr.s_addr));
						cout << " connected " << cs[i] << "\n";

						break;
					}
			}
		}
	}
	
	return 0;
}

char* encrypt_large_text(char* text, unsigned char* key, int &res_length)
{
	int length = strlen((char*)text);
	char* encrypted_text = (char*)malloc(length); assert(encrypted_text);
	char block[16];

	AesCrypto aes;
	int i = 0;
	while (i < length)
	{
		memset(block, 0, 16);
		memcpy(block, text + i, 16);

		unsigned char* enc_block = aes.encrypt((unsigned char*)block, key);
		memcpy(encrypted_text + i, (char*)enc_block, 16);

		i += 16;
	}
	res_length = i;
	return encrypted_text;
}

int aes_get_key_mask(char** argv)
{
	int res = 0;
	for (int i = 0; i < strlen(argv[2]); i++)
		res = res * 10 + (argv[2][i] - '0');
	return res;
}

char* aes_update_key(int mask)
{
	char mask_bytes[] = { ((mask >> 24) & 0xff), ((mask >> 16) & 0xff), ((mask >> 8) & 0xff), (mask & 0xff) };
	char* res = (char*)malloc(16); assert(res);
	for (int i = 0, j = 0; i < 16; i++, j = (j + 1) % 4)
		res[i] = AES_KEY_BASE[i] ^ mask_bytes[j];
	return res;
}

void print_ip(unsigned int a)
{
	cout << ((a >> 24) & 0xff) << ".";
	cout << ((a >> 16) & 0xff) << ".";
	cout << ((a >> 8) & 0xff) << ".";
	cout << (a & 0xff);
}

int ctoint(char* a)
{
	int res = 0;
	while ((*a)) {
		res = res * 10 + ((*a) - '0');
		a++;
	}

	return res;
}

char* createInfo()
{
	char* res;
	int total_size = 0;

	char* local_disks;
	sys_info::localDisksStat(local_disks);
	total_size += strlen(local_disks);

	char* osv = sys_info::take_os_version();
	total_size += strlen(osv);

	char* sysMem;
	sys_info::sysMemoryStatus(sysMem);
	total_size += strlen(sysMem);

	char* time;
	sys_info::getSysTimeStr(time);
	total_size += strlen(time);

	res = (char*)malloc(sizeof(char) * total_size); assert(res);
	strcpy(res, local_disks);
	strcat(res, osv);
	strcat(res, "\n");
	strcat(res, sysMem);
	strcat(res, time);

	return res;
}

int set_non_block_mode(int s)
{
#ifdef _WIN32
	unsigned long mode = 1;
	return ioctlsocket(s, FIONBIO, &mode);
#else
	int fl = fcntl(s, F_GETFL, 0);
	return fcntl(s, F_SETFL, fl | O_NONBLOCK);
#endif
}

int init()
{
#ifdef _WIN32
	WSADATA wsa_data;
	return (0 == WSAStartup(MAKEWORD(2, 2), &wsa_data));
#else
	return 1;
#endif
}

void deinit()
{
#ifdef _WIN32
	WSACleanup();
#else
#endif
}

int sock_err(const char* func, int s)
{
	int err;
#ifdef _WIN32
	err = WSAGetLastError();
#else
	err = errno;
#endif

	printf("%s: error: %d\r\n", func, err);
#ifdef _WIN32
	system("pause");
#endif // _WIN32
	return -1;
}

void s_close(int s)
{
#ifdef _WIN32
	closesocket(s);
#else
	close(s);
#endif
}
