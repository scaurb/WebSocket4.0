#include "websocket_codetool.h"
#include <WinSock2.h>
#include <iostream>
#include <set>
#include <stdio.h>
#pragma comment(lib,"ws2_32.lib")

#define PORT		 10001 
#define DATA_BUFSIZE 4096

SOCKET m_server;
Websocket_Codetool decodetool;

struct PerIOcontext
{
	OVERLAPPED m_Overlapped;
	SOCKET m_sockAccept;
	WSABUF m_wsaBuf;
	char buffer[DATA_BUFSIZE];
	
	bool operator <(const PerIOcontext& r)const{
		return m_sockAccept < r.m_sockAccept;
	}
};

std::set<PerIOcontext> m_clients;
std::set<PerIOcontext>::iterator it;

void process_messages(PerIOcontext* perIOcontext,DWORD msgLen)  //数据处理
{
	if (decodetool.isWSHandShake(perIOcontext->buffer))
	{
		std::string handshakeString =decodetool.GetHandshakeString(perIOcontext->buffer);
		std::cout << perIOcontext->buffer << std::endl;
		std::cout << handshakeString << std::endl;
		send(perIOcontext->m_sockAccept, handshakeString.c_str(), handshakeString.size(), 0);

		m_clients.insert(*perIOcontext);
		return;
	}
	//获取数据类型并根据自己的需求实现相关的操作（根据websocket协议头的opcode）
	WS_FrameType type = decodetool.fetch_websocket_info(perIOcontext->buffer, msgLen); 
	//定义数据缓冲区
	char *outMessage,*responseData;
	outMessage = new char[DATA_BUFSIZE];
	responseData = new char[DATA_BUFSIZE];
	//std::cout << "TYPE: " << type << std::endl;

	switch (type)
	{
	case WS_EMPTY_FRAME:
		break;
	case WS_ERROR_FRAME:
		break;
	case WS_TEXT_FRAME:
		decodetool.wsDecodeFrame(perIOcontext->buffer, msgLen, outMessage);
		decodetool.wsEncodeFrame(outMessage, strlen(outMessage), responseData, WS_TEXT_FRAME);
		std::cout << outMessage << std::endl;
		std::cout << m_clients.size() << std::endl;
		for (it = m_clients.begin(); it != m_clients.end(); it++)
			send(it->m_sockAccept, responseData, strlen(responseData), 0);
		break;
	case WS_BINARY_FRAME:
		break;
	case WS_PING_FRAME:
		break;
	case WS_PONG_FRAME:
		break;
	case WS_OPENING_FRAME:
		break;
	case WS_CLOSING_FRAME:
		closesocket(perIOcontext->m_sockAccept);
		m_clients.erase(*perIOcontext);
		break;
	case WS_CONNECT_FRAME:
		break;
	default:
		break;
	}
	
	delete[] outMessage;
	delete[] responseData;
}

DWORD WINAPI AcceptThread(LPVOID lpParameter)  //接收连接线程
{
	WSADATA wsaData;
	WSAStartup(MAKEWORD(2, 2), &wsaData);
	m_server = WSASocket(AF_INET, SOCK_STREAM, IPPROTO_TCP, NULL, NULL, WSA_FLAG_OVERLAPPED);
	SOCKADDR_IN ServerAddr;
	ServerAddr.sin_family = AF_INET;
	ServerAddr.sin_addr.S_un.S_addr = htonl(INADDR_ANY);
	ServerAddr.sin_port = htons(PORT);
	bind(m_server, (LPSOCKADDR)&ServerAddr, sizeof(ServerAddr));
	listen(m_server, 100);


	printf("listenning...\n");
	int i = 0;
	SOCKADDR_IN ClientAddr;
	int addr_length = sizeof(ClientAddr);

	HANDLE completionPort = (HANDLE)lpParameter;

	while (TRUE)
	{
		PerIOcontext* perIOcontext = (PerIOcontext*)GlobalAlloc(GPTR, sizeof(PerIOcontext));
		SOCKET acceptSocket;
		SOCKADDR_IN acceptAddr;
		int len = sizeof(acceptAddr);
		acceptSocket = accept(m_server, (SOCKADDR*)&acceptAddr, &len);
		printf("接受到客户端连接\n");
		if (SOCKET_ERROR == perIOcontext->m_sockAccept) {   // 接收客户端失败  
			std::cerr << "Accept Socket Error: " << GetLastError() << std::endl;
			system("pause");
			return -1;
		}

		perIOcontext->m_wsaBuf.buf = perIOcontext->buffer;
		perIOcontext->m_wsaBuf.len = 1024;
		perIOcontext->m_sockAccept = acceptSocket;

		CreateIoCompletionPort((HANDLE)(perIOcontext->m_sockAccept), completionPort, (DWORD)perIOcontext, 0);
		DWORD RecvBytes;
		DWORD Flags = 0;
		ZeroMemory(&(perIOcontext->m_Overlapped), sizeof(OVERLAPPED));
		WSARecv(perIOcontext->m_sockAccept, &(perIOcontext->m_wsaBuf), 1, &RecvBytes, &Flags, &(perIOcontext->m_Overlapped), NULL);
	}
	return FALSE;
}

DWORD WINAPI ReceiveThread(LPVOID lpParameter) //接收数据线程
{
	HANDLE completionPort = (HANDLE)lpParameter;
	DWORD BytesTransferred;
	PerIOcontext* perIOcontext;
	LPOVERLAPPED IpOverlapped = NULL;
	while (true)
	{
		BOOL ret = GetQueuedCompletionStatus(completionPort, &BytesTransferred, (PULONG_PTR)&perIOcontext, &IpOverlapped, INFINITE);
		//std::cout << "msgLen:" << BytesTransferred << std::endl;
		process_messages(perIOcontext, BytesTransferred);

		if (BytesTransferred == 0)
			printf("获得字节为0，disconnect\n");

		//printf("客户端：%s\n", perIOcontext->buffer);

		memset(perIOcontext->buffer, 0, DATA_BUFSIZE);
		DWORD RecvBytes;
		DWORD Flags = 0;
		//system("pause");
		WSARecv(perIOcontext->m_sockAccept, &(perIOcontext->m_wsaBuf), 1, &RecvBytes, &Flags, &(perIOcontext->m_Overlapped), NULL);
	}
	return FALSE;
}

int main()
{
	system("chcp 65001"); //控制台中文乱码问题

	HANDLE completionPort = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);

	if (NULL == completionPort) {    // 创建IO内核对象失败  
		std::cout << "CreateIoCompletionPort failed. Error:" << GetLastError() << std::endl;
		system("pause");
		return 0;
	}

	HANDLE hThreads[2];
	hThreads[0] = CreateThread(NULL, 0, AcceptThread, completionPort, NULL, NULL);
	hThreads[1] = CreateThread(NULL, 0, ReceiveThread, completionPort, NULL, NULL);
	WaitForMultipleObjects(2, hThreads, TRUE, INFINITE);
	printf("exit\n");
	CloseHandle(hThreads[0]);
	CloseHandle(hThreads[1]);
	return 0;
}