// ConsoleApplication2.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include <iostream>

#include "aes.h"
#include "filters.h"
#include "secblock.h"
#include "hex.h"
#include "modes.h"
#include "osrng.h"

using namespace std;
using namespace CryptoPP;

//final
byte* voidByteArray(const int length) {
	byte* rtn = new byte[length];
	memset(rtn, 0x00, length);
	return rtn;
}

byte* hash(char* txt) {
	size_t messageLen = std::strlen(txt) + 1;
	byte sha_out[16];
	memset(sha_out, 0x00, 16);
	SHA256 sha;
	sha.CalculateDigest(sha_out, (byte*)txt, messageLen);
	return sha_out;
}

void encode(byte* hash_key, byte* input) {
	SecByteBlock key(hash_key, 16);
	SecByteBlock iv(voidByteArray(16), 16);
	size_t messageLen = std::strlen((char*)input) + 1;
	CBC_Mode<AES>::Encryption cfbEncryption(key, key.size(), iv);
	cfbEncryption.ProcessData(input, input, messageLen);
}

void decode(byte* hash_key, byte* input) {
	SecByteBlock key(hash_key, 16);
	SecByteBlock iv(voidByteArray(16), 16);
	size_t messageLen = std::strlen((char*)input) + 1;
	CBC_Mode<AES>::Decryption cfbDecryption(key, key.size(), iv);
	cfbDecryption.ProcessData(input, input, messageLen);
}

byte* HexDecode(const string str) {
	string decoded;
	auto cstr = (byte*)str.c_str();

	HexDecoder decoder;
	decoder.Put((byte*)str.data(), str.size());
	decoder.MessageEnd();

	word64 size = decoder.MaxRetrievable();
	if (size&& size <= SIZE_MAX)
	{
		decoded.resize(size);
		decoder.Get((byte*)&decoded[0], decoded.size());
	}
	return (byte*)decoded.data();
}

string HexEncode(const byte* barray) {
	string encoded;

	HexEncoder encoder;
	encoder.Put(barray, strlen((char*)barray));
	encoder.MessageEnd();

	word64 size = encoder.MaxRetrievable();
	if (size)
	{
		encoded.resize(size);
		encoder.Get((byte*)&encoded[0], encoded.size());
	}
	return encoded;
}


int main()
{
	byte plainText[] = "Hello! How are you.";

	encode(voidByteArray(16), plainText);
	cout << HexEncode(plainText) << endl;
	decode(voidByteArray(16), plainText);
	cout << plainText << endl;


}