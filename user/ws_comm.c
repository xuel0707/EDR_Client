#include "header.h"

#define SHA1CircularShift(bits, word) ((((word) << (bits)) & 0xFFFFFFFF) | ((word) >> (32 - (bits))))

int tolower(int c)
{
	if (c >= 'A' && c <= 'Z') {
		return c + 'a' - 'A';
	} else {
		return c;
	}
}

/* 生成随机字符串 */
void creat_random_string(char *buff, unsigned int len)
{
	unsigned int i = 0;
	uint8_t temp = 0;

	srand((int)time(0));
	for (i = 0; i < len; i++) {
		temp = (uint8_t)(rand() % 256);

		/* 0会干扰对字符串长度的判断 */
		if (temp == 0) {
			temp = 128;
		}

		buff[i] = temp;
	}

	return;
}

/* 生成随机数字字符串 */
void creat_random_number(char *buff, unsigned int len)
{
	unsigned int i = 0;
	int temp = 0;

	srand((int)time(0));
	for (i = 0; i < len; i++) {
		temp = (rand() % 10);

		buff[i] = '0' + temp;
	}

	return;
}

/* 十六进制转换为十进制 */
int htoi(const char s[], int start, int len)
{       
	int i = 0, j = 0;
	int number = 0, ret = 0;
        
	/* 判断是否以0x或者0X开头 */
	if (s[0] == '0' && (s[1] == 'x' || s[1] == 'X')) {
		i = 2;
	} else {
		i = 0;
	}

	j = 0;
	for (i += start; (s[i] >= '0' && s[i] <= '9') || (s[i] >= 'a' && s[i] <= 'f') || (s[i] >= 'A' && s[i] <= 'F'); i++) {
		if (j >= len) {
			break;
		}

		ret = tolower(s[i]);
		if (tolower(s[i]) > '9') {
			number = 16 * number + (10 + ret - 'a');
		} else {
			number = 16 * number + (ret - '0');
		}
		j++;
	}

	return number;
}
/* base64编/解码用的基础字符集 */
const char ws_base64char[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

/* ascii编码为base64格式 */
int ws_base64_encode(const uint8_t *bindata, char *base64, int binlength)
{
	int i = 0, j = 0;
	uint8_t current = 0;

	for (i = 0, j = 0; i < binlength; i += 3) {
		current = (bindata[i] >> 2);
		current &= (uint8_t)0x3F;
		base64[j++] = ws_base64char[(int)current];
		current = ((uint8_t)(bindata[i] << 4)) & ((uint8_t)0x30);

		if (i + 1 >= binlength) {
			base64[j++] = ws_base64char[(int)current];
			base64[j++] = '=';
			base64[j++] = '=';
			break;
		}

		current |= ((uint8_t)(bindata[i + 1] >> 4)) & ((uint8_t)0x0F);
		base64[j++] = ws_base64char[(int)current];
		current = ((uint8_t)(bindata[i + 1] << 2)) & ((uint8_t)0x3C);

		if (i + 2 >= binlength) {
			base64[j++] = ws_base64char[(int)current];
			base64[j++] = '=';
			break;
		}

		current |= ((uint8_t)(bindata[i + 2] >> 6)) & ((uint8_t)0x03);
		base64[j++] = ws_base64char[(int)current];
		current = ((uint8_t)bindata[i + 2]) & ((uint8_t)0x3F);
		base64[j++] = ws_base64char[(int)current];
	}

	base64[j] = '\0';
	return j;
}

/* ====================加密方法 sha1哈希==================== */
typedef struct SHA1Context
{
	uint32_t Message_Digest[5];
	uint32_t Length_Low;
	uint32_t Length_High;
	uint8_t Message_Block[64];
	int32_t Message_Block_Index;
	int32_t Computed;
	int32_t Corrupted;
} SHA1Context;

void SHA1ProcessMessageBlock(SHA1Context *context)
{
	const uint32_t K[] = {0x5A827999, 0x6ED9EBA1, 0x8F1BBCDC, 0xCA62C1D6};
	int32_t t;
	uint32_t temp;
	uint32_t W[80];
	uint32_t A, B, C, D, E;

	for (t = 0; t < 16; t++) {
		W[t] = ((uint32_t)context->Message_Block[t * 4]) << 24;
		W[t] |= ((uint32_t)context->Message_Block[t * 4 + 1]) << 16;
		W[t] |= ((uint32_t)context->Message_Block[t * 4 + 2]) << 8;
		W[t] |= ((uint32_t)context->Message_Block[t * 4 + 3]);
	}

	for (t = 16; t < 80; t++) {
		W[t] = SHA1CircularShift(1, W[t - 3] ^ W[t - 8] ^ W[t - 14] ^ W[t - 16]);
	}

	A = context->Message_Digest[0];
	B = context->Message_Digest[1];
	C = context->Message_Digest[2];
	D = context->Message_Digest[3];
	E = context->Message_Digest[4];

	for (t = 0; t < 20; t++) {
		temp = SHA1CircularShift(5, A) + ((B & C) | ((~B) & D)) + E + W[t] + K[0];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 20; t < 40; t++) {
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[1];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 40; t < 60; t++) {
		temp = SHA1CircularShift(5, A) + ((B & C) | (B & D) | (C & D)) + E + W[t] + K[2];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	for (t = 60; t < 80; t++) {
		temp = SHA1CircularShift(5, A) + (B ^ C ^ D) + E + W[t] + K[3];
		temp &= 0xFFFFFFFF;
		E = D;
		D = C;
		C = SHA1CircularShift(30, B);
		B = A;
		A = temp;
	}

	context->Message_Digest[0] = (context->Message_Digest[0] + A) & 0xFFFFFFFF;
	context->Message_Digest[1] = (context->Message_Digest[1] + B) & 0xFFFFFFFF;
	context->Message_Digest[2] = (context->Message_Digest[2] + C) & 0xFFFFFFFF;
	context->Message_Digest[3] = (context->Message_Digest[3] + D) & 0xFFFFFFFF;
	context->Message_Digest[4] = (context->Message_Digest[4] + E) & 0xFFFFFFFF;
	context->Message_Block_Index = 0;
}

void SHA1Reset(SHA1Context *context)
{
	context->Length_Low = 0;
	context->Length_High = 0;
	context->Message_Block_Index = 0;

	context->Message_Digest[0] = 0x67452301;
	context->Message_Digest[1] = 0xEFCDAB89;
	context->Message_Digest[2] = 0x98BADCFE;
	context->Message_Digest[3] = 0x10325476;
	context->Message_Digest[4] = 0xC3D2E1F0;

	context->Computed = 0;
	context->Corrupted = 0;
}

void SHA1PadMessage(SHA1Context *context)
{
	if (context->Message_Block_Index > 55) {
		context->Message_Block[context->Message_Block_Index++] = 0x80;

		while (context->Message_Block_Index < 64) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}

        	SHA1ProcessMessageBlock(context);
		while (context->Message_Block_Index < 56) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	} else {
		context->Message_Block[context->Message_Block_Index++] = 0x80;

		while (context->Message_Block_Index < 56) {
			context->Message_Block[context->Message_Block_Index++] = 0;
		}
	}

	context->Message_Block[56] = (context->Length_High >> 24) & 0xFF;
	context->Message_Block[57] = (context->Length_High >> 16) & 0xFF;
	context->Message_Block[58] = (context->Length_High >> 8) & 0xFF;
	context->Message_Block[59] = (context->Length_High) & 0xFF;
	context->Message_Block[60] = (context->Length_Low >> 24) & 0xFF;
	context->Message_Block[61] = (context->Length_Low >> 16) & 0xFF;
	context->Message_Block[62] = (context->Length_Low >> 8) & 0xFF;
	context->Message_Block[63] = (context->Length_Low) & 0xFF;

	SHA1ProcessMessageBlock(context);
}

int32_t SHA1Result(SHA1Context *context)
{
	if (context->Corrupted) {
		return 0;
	}

	if (!context->Computed) {
		SHA1PadMessage(context);
		context->Computed = 1;
	}

	return 1;
}

void SHA1Input(SHA1Context *context, const char *message_array, uint32_t length)
{
	if (!length) {
		return;
	}

	if (context->Computed || context->Corrupted) {
		context->Corrupted = 1;
		return;
	}

	while (length-- && !context->Corrupted) {
		context->Message_Block[context->Message_Block_Index++] = (*message_array & 0xFF);

		context->Length_Low += 8;

		context->Length_Low &= 0xFFFFFFFF;
		if (context->Length_Low == 0) {
			context->Length_High++;
			context->Length_High &= 0xFFFFFFFF;
			if (context->Length_High == 0) {
				context->Corrupted = 1;
			}
		}

		if (context->Message_Block_Index == 64) {
			SHA1ProcessMessageBlock(context);
		}
		message_array++;

	}
}

char *sha1_hash(const char *source)
{
	SHA1Context sha;
	char *buf = NULL; //[128];

	SHA1Reset(&sha);
	SHA1Input(&sha, source, strlen(source));

	if (!SHA1Result(&sha)) {
		MON_ERROR("SHA1 ERROR: Could not compute message digest");
		return NULL;
	} else {
		buf = (char *)malloc(128);
		if (buf == NULL) {
			MON_ERROR("malloc sha1 hash buf failed\n");
			return NULL;
		}
		memset(buf, 0, 128);

		sprintf(buf, "%08X%08X%08X%08X%08X",
			sha.Message_Digest[0],
			sha.Message_Digest[1],
			sha.Message_Digest[2],
			sha.Message_Digest[3],
			sha.Message_Digest[4]);

		return buf;
	}
}
/* ====================加密方法 sha1哈希==================== */
