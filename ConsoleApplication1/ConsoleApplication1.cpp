// ConsoleApplication1.cpp : 此文件包含 "main" 函数。程序执行将在此处开始并结束。
//

#include "pch.h"
#include "aes.h"
#include "filters.h"
#include "secblock.h"
#include "hex.h"
#include "modes.h"

using namespace std;
using namespace CryptoPP;

string AES_CTR_Encrypt(const char *, const char *);


int main()
{
	cout << "Hello World!\n";
	string* str = new string("123456");
	unsigned char* seq0 = (unsigned char*)str->c_str();

	cout << seq0 << "\n";

	auto rtn=AES_CTR_Encrypt("123456789012", "123456");












}

// 运行程序: Ctrl + F5 或调试 >“开始执行(不调试)”菜单
// 调试程序: F5 或调试 >“开始调试”菜单

// 入门提示: 
//   1. 使用解决方案资源管理器窗口添加/管理文件
//   2. 使用团队资源管理器窗口连接到源代码管理
//   3. 使用输出窗口查看生成输出和其他消息
//   4. 使用错误列表窗口查看错误
//   5. 转到“项目”>“添加新项”以创建新的代码文件，或转到“项目”>“添加现有项”以将现有代码文件添加到项目
//   6. 将来，若要再次打开此项目，请转到“文件”>“打开”>“项目”并选择 .sln 文件

byte* voidByteArray(const int length) {
	byte* rtn = new byte[length];
	memset(rtn, 0x00, length);
	return rtn;
}

SecByteBlock HexDecodeString(const char *hex)
{
	StringSource ss(hex, true, new HexDecoder);
	SecByteBlock result((size_t)ss.MaxRetrievable());
	ss.Get(result, result.size());
	return result;
}

SecByteBlock HexDecode(const byte* byteArray, const int len) {
	SecByteBlock result(byteArray, len);
	return result;
}

string AES_CTR_Encrypt(const char *hexKey, const char *input)
{
	string rtn_buffer;
	SecByteBlock key = HexDecodeString(hexKey);
	SecByteBlock iv = HexDecode(voidByteArray(8), 8);
	CTR_Mode<AES>::Encryption aes(key, key.size(), iv);
	StreamTransformationFilter stf(aes, new StringSink(rtn_buffer));
	stf.Put((byte*)input, strlen(input));
	stf.MessageEnd();
	return rtn_buffer;
}