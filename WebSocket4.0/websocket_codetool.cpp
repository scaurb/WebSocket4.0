#include "websocket_codetool.h"
#include "base64.h"

#include <WinSock2.h>
Websocket_Codetool::Websocket_Codetool()
{

}

Websocket_Codetool::~Websocket_Codetool()
{
}

int Websocket_Codetool::wsDecodeFrame(const char* frameData, int len, char* outMessage)
{
	int ret = WS_OPENING_FRAME;

	const int frameLength = len;
	if (frameLength < 2)
	{
		ret = WS_ERROR_FRAME;
	}

	// 检查扩展位并忽略
	if ((frameData[0] & 0x70) != 0x0)
	{
		ret = WS_ERROR_FRAME;
	}

	// fin位: 为1表示已接收完整报文, 为0表示继续监听后续报文
	ret = (frameData[0] & 0x80);

	if ((frameData[0] & 0x80) != 0x80)
	{
		ret = WS_ERROR_FRAME;
	}

	// mask位, 为1表示数据被加密
	if ((frameData[1] & 0x80) != 0x80)
	{
		ret = WS_ERROR_FRAME;
	}

	// 操作码
	uint16_t payloadLength = 0;
	uint8_t payloadFieldExtraBytes = 0;
	uint8_t opcode = static_cast<uint8_t>(frameData[0] & 0x0f);

	//std::cout << "mask:" << ((frameData[1] & 0x80) != 0x80) << std::endl;
	//std::cout << "frameLength: " << frameLength << std::endl;
	//std::cout << "payloadLength: " << payloadLength << std::endl;
	//std::cout << "payloadFieldExtraBytes: " << payloadFieldExtraBytes << std::endl;
	//std::cout << "opcode: " << opcode << std::endl;


	if (opcode == WS_TEXT_FRAME)
	{
		// 处理utf-8编码的文本帧
		ret = WS_TEXT_FRAME;
		payloadLength = static_cast<uint16_t>(frameData[1] & 0x7f);
		if (payloadLength == 0x7e)
		{
			uint16_t payloadLength16b = 0;
			payloadFieldExtraBytes = 2;
			memcpy(&payloadLength16b, &frameData[2], payloadFieldExtraBytes);
			payloadLength = ntohs(payloadLength16b);
		}
		else if (payloadLength == 0x7f)
		{
			// 数据过长,暂不支持
			ret = WS_ERROR_FRAME;
		}
	}
	else if (opcode == WS_BINARY_FRAME || opcode == WS_PING_FRAME || opcode == WS_PONG_FRAME)
	{
		// 二进制/ping/pong帧暂不处理
	}
	else if (opcode == WS_CLOSING_FRAME)
	{
		ret = WS_CLOSING_FRAME;
	}
	else
	{
		ret = WS_ERROR_FRAME;
	}


	// 数据解码
	if ((ret != WS_ERROR_FRAME) && (payloadLength > 0))
	{
		// header: 2字节, masking key: 4字节
		const char *maskingKey = &frameData[2 + payloadFieldExtraBytes];
		char *payloadData = new char[payloadLength + 1];
		memset(payloadData, 0, payloadLength + 1);
		memcpy(payloadData, &frameData[2 + payloadFieldExtraBytes + 4], payloadLength);
		for (int i = 0; i < payloadLength; i++)
		{
			payloadData[i] = payloadData[i] ^ maskingKey[i % 4];
		}

		//outMessage = payloadData;
		int totLen = payloadLength;
		memcpy(outMessage, payloadData, totLen);
		outMessage[totLen] = 0x00;
		delete[] payloadData;
	}
	return ret;
}

int Websocket_Codetool::wsEncodeFrame(const char * inMessage, int messageLen, char* outFrame, enum WS_FrameType frameType)
{
	int ret = WS_EMPTY_FRAME;
	const uint32_t messageLength = messageLen;

	if (messageLength > 32767)
	{
		// 暂不支持这么长的数据
		return WS_ERROR_FRAME;
	}

	uint8_t payloadFieldExtraBytes = (messageLength <= 0x7d) ? 0 : 2;
	// header: 2字节, mask位设置为0(不加密), 则后面的masking key无须填写, 省略4字节
	uint8_t frameHeaderSize = 2 + payloadFieldExtraBytes;
	uint8_t *frameHeader = new uint8_t[frameHeaderSize];
	memset(frameHeader, 0, frameHeaderSize);
	// fin位为1, 扩展位为0, 操作位为frameType
	frameHeader[0] = static_cast<uint8_t>(0x80 | frameType);

	// 填充数据长度
	if (messageLength <= 0x7d)
	{
		frameHeader[1] = static_cast<uint8_t>(messageLength);
	}
	else
	{
		frameHeader[1] = 0x7e;
		uint16_t len = htons(messageLength);
		memcpy(&frameHeader[2], &len, payloadFieldExtraBytes);
	}

	// 填充数据
	uint32_t frameSize = frameHeaderSize + messageLength;
	char *frame = new char[frameSize + 1];
	memcpy(frame, frameHeader, frameHeaderSize);
	memcpy(frame + frameHeaderSize, inMessage, messageLength);
	frame[frameSize] = '\0';

	//outFrame = frame;
	memcpy(outFrame, frame, frameSize);
	outFrame[frameSize] = 0x00;

	delete[] frame;
	delete[] frameHeader;
	return ret;
}

bool Websocket_Codetool::isWSHandShake(const char* request)
{
	std::string str = request;
	size_t i = str.find("GET");
	if (i == std::string::npos) {
		return false;
	}
	return true;
}

std::string Websocket_Codetool::getKey(std::string strKey)
{
	SHA1 sha;
	strKey += MAGICSTRING;
	//strcat(strKey, MAGICSTRING);
	unsigned int iDigSet[5];
	sha.Reset();
	sha << strKey.c_str();
	sha.Result(iDigSet);

	for (int i = 0; i < 5; i++)iDigSet[i] = htonl(iDigSet[i]);			//将字节转换成网络字节顺序

	//进行base64编码
	base64 base64code;
	//strcpy(strKey , base64code.base64_encode(reinterpret_cast<const unsigned char*>(iDigSet), 20).c_str() );
	strKey = base64code.base64_encode(reinterpret_cast<const unsigned char*>(iDigSet), 20);
	return strKey;
}

std::string Websocket_Codetool::GetHandshakeString(std::string request)
{
	std::string response;
	int pos = request.find("Sec-WebSocket-Key: ");
	response += "HTTP/1.1 101 Switching Protocols\r\n";
	response += "Connection: upgrade\r\n";
	response += "Access-Control-Allow-Credentials:true\r\n";
	response += "Access-Control-Allow-Headers:content-type\r\n";
	response += "Sec-WebSocket-Accept: ";

	std::string strKey = request.substr(pos + 19, 24);
	//std::cout << "oldKey" << strKey << std::endl;

	std::string newKey = getKey(strKey.c_str());
	//std::cout << "newKey" << newKey << std::endl;

	response += newKey + "\r\n";
	response += "Upgrade: websocket\r\n\r\n";

	/*std::cout << response << std::endl;
	std::string s = "puVOuWb7rel6z2AVZBKnfw==\r";
	std::cout << getKey(s) << std::endl;*/
	return response;
}

WS_FrameType Websocket_Codetool::fetch_websocket_info(const char *frameData, int len)
{
	int ret = WS_OPENING_FRAME;

	//const char *frameData = request.c_str();
	const int frameLength = len;
	if (frameLength < 2)
	{
		ret = WS_ERROR_FRAME;
	}

	// 检查扩展位并忽略
	if ((frameData[0] & 0x70) != 0x0)
	{
		ret = WS_ERROR_FRAME;
	}

	// fin位: 为1表示已接收完整报文, 为0表示继续监听后续报文
	ret = (frameData[0] & 0x80);

	if ((frameData[0] & 0x80) != 0x80)
	{
		ret = WS_ERROR_FRAME;
	}

	// mask位, 为1表示数据被加密
	if ((frameData[1] & 0x80) != 0x80)
	{
		ret = WS_ERROR_FRAME;
	}

	// 操作码
	uint16_t payloadLength = 0;
	uint8_t payloadFieldExtraBytes = 0;
	uint8_t opcode = static_cast<uint8_t>(frameData[0] & 0x0f);

	//std::cout << "mask:" << ((frameData[1] & 0x80) != 0x80) << std::endl;
	//std::cout << "frameLength: " << frameLength << std::endl;
	//std::cout << "payloadLength: " << payloadLength << std::endl;
	//std::cout << "payloadFieldExtraBytes: " << payloadFieldExtraBytes << std::endl;
	//std::cout << "opcode: " << opcode << std::endl;
	if (opcode == WS_TEXT_FRAME)
	{
		ret = WS_TEXT_FRAME;
		if (payloadLength == 0x7f)
		{
			// 数据过长,暂不支持
			ret = WS_ERROR_FRAME;
		}
	}
	else if (opcode == WS_BINARY_FRAME || opcode == WS_PING_FRAME || opcode == WS_PONG_FRAME)
	{
		// 二进制/ping/pong帧暂不处理
	}
	else if (opcode == WS_CLOSING_FRAME)
	{
		ret = WS_CLOSING_FRAME;
	}
	else
	{
		ret = WS_ERROR_FRAME;
	}

	return WS_FrameType(ret);
}

int Websocket_Codetool::fetch_fin(char * msg, int & pos)
{
	fin_ = (unsigned char)msg[pos] >> 7;
	return 0;
}

int Websocket_Codetool::fetch_opcode(char * msg, int & pos)
{
	opcode_ = msg[pos] & 0x0f;
	pos++;
	return 0;
}

int Websocket_Codetool::fetch_mask(char * msg, int & pos)
{
	mask_ = (unsigned char)msg[pos] >> 7;
	return 0;
}

int Websocket_Codetool::fetch_masking_key(char * msg, int & pos)
{
	if (mask_ != 1)
		return 0;
	for (int i = 0; i < 4; i++)
		masking_key_[i] = msg[pos + i];
	pos += 4;
	return 0;
}

int Websocket_Codetool::fetch_payload_length(char * msg, int & pos)
{
	payload_length_ = msg[pos] & 0x7f;
	pos++;
	if (payload_length_ == 126) {
		uint16_t length = 0;
		memcpy(&length, msg + pos, 2);
		pos += 2;
		payload_length_ = ntohs(length);
	}
	else if (payload_length_ == 127) {
		uint32_t length = 0;
		memcpy(&length, msg + pos, 4);
		pos += 4;
		payload_length_ = ntohl(length);
	}
	return 0;
}

int Websocket_Codetool::fetch_payload(char * msg, int & pos)
{
	memset(payload_, 0, sizeof(payload_));
	if (mask_ != 1) {
		memcpy(payload_, msg + pos, payload_length_);
	}
	else {
		for (int i = 0; i < payload_length_; i++) {
			int j = i % 4;
			payload_[i] = msg[pos + i] ^ masking_key_[j];
		}
	}
	pos += payload_length_;
	return 0;
}
