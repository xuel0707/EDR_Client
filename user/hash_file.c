#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/md5.h>
#include <openssl/sha.h>

#include "header.h"
#include "logger.h"

void md5_hash_string (unsigned char hash[MD5_DIGEST_LENGTH], char outputBuffer[33])
{
        int i;

        for (i = 0; i < MD5_DIGEST_LENGTH; i++) {
                sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
        }

        outputBuffer[32] = 0;
}

int md5_string(char *string, char output[33])
{
	MD5_CTX md5_ctx;
	unsigned char hash[MD5_DIGEST_LENGTH] = {0};

        if (string == NULL) {
                return -1;
        }

	MD5_Init(&md5_ctx);
        MD5_Update(&md5_ctx, string, strlen(string));

	MD5_Final(hash, &md5_ctx);
        md5_hash_string(hash, output);

        return 0;
}

int md5_file (char *path, char output[33])
{
        int len = 0;
	FILE *fp = NULL;
        MD5_CTX md5_ctx;
	unsigned char buffer[1024] = {0};
        unsigned char hash[MD5_DIGEST_LENGTH] = {0};

        if ((fp = fopen(path, "rb")) == NULL) {
		//MON_ERROR("md5 open file(%s) failed!\n", path);
		return -1;
	}

        MD5_Init(&md5_ctx);

        while ((len = fread(buffer, 1, 1024, fp)) > 0) {
                MD5_Update(&md5_ctx, buffer, len);
        }

        MD5_Final(hash, &md5_ctx);
        md5_hash_string(hash, output);

        fclose(fp);
        return 0;
}

int md5_filter_large_file (char *path, char output[33])
{
        int len = 0;
	FILE *fp = NULL;
        MD5_CTX md5_ctx;
	unsigned char buffer[1024] = {0};
        unsigned char hash[MD5_DIGEST_LENGTH] = {0};
	struct stat st = {0};

	if (stat(path, &st) < 0) {
		return -1;
	}

	if(st.st_size > 20*MB_SIZE) {
		memset(output, 0, S_MD5LEN);
		return 0;
	}

        if ((fp = fopen(path, "rb")) == NULL) {
		//MON_ERROR("md5 open file(%s) failed!\n", path);
		return -1;
	}

        MD5_Init(&md5_ctx);

        while ((len = fread(buffer, 1, 1024, fp)) > 0) {
                MD5_Update(&md5_ctx, buffer, len);
        }

        MD5_Final(hash, &md5_ctx);
        md5_hash_string(hash, output);

        fclose(fp);
        return 0;
}

void sha256_hash_string (unsigned char hash[SHA256_DIGEST_LENGTH], char outputBuffer[65])
{
        int i;

        for (i = 0; i < SHA256_DIGEST_LENGTH; i++) {
                sprintf(outputBuffer + (i * 2), "%02x", hash[i]);
        }

        outputBuffer[64] = 0;
}


int sha256_file (char* path, char output[65])
{
	int len = 0;
	FILE *fp = NULL;
        SHA256_CTX sha256;
	unsigned char buffer[1024] = {0};
        unsigned char hash[SHA256_DIGEST_LENGTH] = {0};

        if((fp = fopen(path, "rb")) == NULL) { 
		//MON_ERROR("sha256 open file(%s) failed!\n", path);
		return -1;
	}

        SHA256_Init(&sha256);

        while ((len = fread(buffer, 1, 1024, fp)) > 0) {
                SHA256_Update(&sha256, buffer, len);
        }

        SHA256_Final(hash, &sha256);
        sha256_hash_string(hash, output);

        fclose(fp);
        return 0;
}

#if 0
int main (int argc, char** argv)
{
	int ret = 0;
        char md5_hash[65] = {0};
        char sha256_hash[65] = {0};

        ret = md5_file("file.txt", md5_hash);
	if (ret == -1)
		printf("md5_file failed! \n");
	else 
		printf("--md5 hash:%s---\n",md5_hash);
	
        ret = sha256_file("file.txt", sha256_hash);
	if (ret == -1)
		printf("sha256_file failed! \n");
	else
		printf("--sha256 hash:%s---\n",sha256_hash);
}
#endif
