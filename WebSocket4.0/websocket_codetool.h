#pragma once
#include <string>
/*用于处理websocket中的所有编码相关,解析websocket格式
1.解析websocket连接请求中的sec，并生成对应的accept码，（通过sha1与base64编码）
2.解析来自客户端的websocket格式数据
3.封装数据成为websocket格式，用于发送到客户端*/

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
	//解码
	int wsDecodeFrame(const char* inFrame, int len, char* outMessage); //解码websocket格式的数据（来自web客户端）																	
	//封装数据（数据加上websocket头部）
	int wsEncodeFrame(const char* inMessage, int len, char* outFrame, enum WS_FrameType frameType);

	bool isWSHandShake(const char* request);  ////判断是否为客户端发送的升级WS握手请求，"Upgrade: websocket"
	std::string getKey(std::string strKey);          //解码client的key（sha1 + base64），得到解码后的key
	std::string GetHandshakeString(std::string request);

	WS_FrameType fetch_websocket_info(const char *frameData, int len); //获取消息类型

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