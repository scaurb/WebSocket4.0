#pragma once

#ifndef BASE64_H
#define BASE64_H

#include <string>
#include "sha1.h"
static const std::string base64_chars =
"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
"abcdefghijklmnopqrstuvwxyz"
"0123456789+/";

const std::string MAGICSTRING = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";

class base64
{
public:
	base64();
	~base64();

	std::string base64_encode(unsigned char const* bytes_to_encode, unsigned int in_len);

private:

};

#endif //BASE64_H