#pragma once
#include <string>
/*���ڴ���websocket�е����б������,����websocket��ʽ
1.����websocket���������е�sec�������ɶ�Ӧ��accept�룬��ͨ��sha1��base64���룩
2.�������Կͻ��˵�websocket��ʽ����
3.��װ���ݳ�Ϊwebsocket��ʽ�����ڷ��͵��ͻ���*/

enum WS_Status
{
	WS_STATUS_CONNECT = 0,
	WS_STATUS_UNCONNECT = 1,
};

enum WS_FrameType
{
	WS_EMPTY_FRAME = 0xF0,
	WS_ERROR_FRAME = 0xF1,
	WS_TEXT_FRAME = 0x01,
	WS_BINARY_FRAME = 0x02,
	WS_PING_FRAME = 0x09,
	WS_PONG_FRAME = 0x0A,
	WS_OPENING_FRAME = 0xF3,
	WS_CLOSING_FRAME = 0x08,
	WS_CONNECT_FRAME = 0X07
};
class Websocket_Codetool
{
public:
	Websocket_Codetool();
	~Websocket_Codetool();
	//����
	int wsDecodeFrame(const char* inFrame, int len, char* outMessage); //����websocket��ʽ�����ݣ�����web�ͻ��ˣ�																	
	//��װ���ݣ����ݼ���websocketͷ����
	int wsEncodeFrame(const char* inMessage, int len, char* outFrame, enum WS_FrameType frameType);

	bool isWSHandShake(const char* request);  ////�ж��Ƿ�Ϊ�ͻ��˷��͵�����WS��������"Upgrade: websocket"
	std::string getKey(std::string strKey);          //����client��key��sha1 + base64�����õ�������key
	std::string GetHandshakeString(std::string request);

	WS_FrameType fetch_websocket_info(const char *frameData, int len); //��ȡ��Ϣ����

private:
	int fetch_fin(char *msg, int &pos);
	int fetch_opcode(char *msg, int &pos);
	int fetch_mask(char *msg, int &pos);
	int fetch_masking_key(char *msg, int &pos);
	int fetch_payload_length(char *msg, int &pos);
	int fetch_payload(char *msg, int &pos);

private:
	uint8_t fin_;
	uint8_t opcode_;
	uint8_t mask_;
	uint8_t masking_key_[4];
	uint64_t payload_length_;
	char payload_[2048];


};