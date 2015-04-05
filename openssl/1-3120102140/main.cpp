//
//  main.cpp
//  openssl
//
//  Created by Xinbao Dong on 15/4/4.
//  Copyright (c) 2015年 com.dongxinbao. All rights reserved.
//

#include <iostream>
#include "MyRSA.h"


using namespace std;

int main(int argc, const char * argv[]) {
    Key *key = new Key();
    key->generateNewKey("pub.pem", "pri.pem");
    MyRSA *rsa = new MyRSA(key);
    
    printf("读取file.pdf文件中…\n");
    FILE *originalFile = fopen("file.pdf", "rb");
    if (originalFile == NULL) {
        printf("File not exits!\n");
        exit(0);
    }
    fseek(originalFile, 0, SEEK_END);
    int originalSize = ftell(originalFile);
    rewind(originalFile);
    unsigned char *originalBuffer = (unsigned char *)malloc(sizeof(char) * originalSize);
    if (originalBuffer == NULL) {
        printf("Memory Error!\n");
        exit(0);
    }
    if (fread(originalBuffer, 1, originalSize, originalFile) != originalSize) {
        printf("File load error!\n");
        exit(0);
    }
    fclose(originalFile);
    printf("文件读取成功，长度为%d\n", originalSize);
    
    printf("签名中…\n");
    //sign
    unsigned char *signature;
    unsigned int signatureLength;
    if (rsa->mySign((unsigned char *)originalBuffer, originalSize, (unsigned char **)&signature, signatureLength) <= 0) {
        printf("Signature Error!\n");
    }
    
    
    //save signature
    FILE *signedFile = fopen("signture.pdf", "wb");
    if (signedFile == NULL) {
        printf("Create signed file error!\n");
        exit(0);
    }
    fwrite(originalBuffer, 1, originalSize, signedFile);
    fwrite(signature, 1, signatureLength, signedFile);
    fclose(signedFile);
    printf("签名成功，签名长度为%d，总长度为%d，已保存签名后的文件至signture.pdf\n", signatureLength, signatureLength + originalSize);
    
    //reload the signed file
    signedFile = fopen("signture.pdf", "rb");
    if (signedFile == NULL) {
        printf("Signed file not exits!\n");
        exit(0);
    }
    fseek(signedFile, 0, SEEK_END);
    int signedFileSize = ftell(signedFile);
    rewind(signedFile);
    unsigned char * signedBuffer = (unsigned char *)malloc(sizeof(char) * signedFileSize);
    if (signedBuffer == NULL) {
        printf("Memory Error!\n");
        exit(0);
    }
    if (fread(signedBuffer, 1, signedFileSize, signedFile) != signedFileSize) {
        printf("Signed File load error!\n");
        exit(0);
    }
    fclose(signedFile);
    
    
    printf("加密签名后的文件中…\n");
    //encrypt and save
    
    FILE *encryptedFile = fopen("encrypted.pdf", "wb");
    if (encryptedFile == NULL) {
        printf("Create encrypted file error!\n");
        exit(0);
    }
    
    unsigned char *encryptedBuffer;
    unsigned int encryptedLength;
    int i = 0;
    while (i < signedFileSize) {
        if (rsa->myEncrypt((unsigned char *)(signedBuffer + i), 100, (unsigned char **)&encryptedBuffer, encryptedLength) <= 0) {
            printf("Signed File encrypt error!\n");
            exit(0);
        }
        fwrite(encryptedBuffer, 1, encryptedLength, encryptedFile);
        
        free(encryptedBuffer);
        i +=  100;              //100为单位加密，其实只要小于128-11就行了。
    }

    fclose(encryptedFile);
    printf("加密成功，长度为%d，已保存加密后的文件至encrypted.pdf\n", signedFileSize / 100 * 128);
    printf("解密中…\n");
    
    //decrypt the file
    encryptedFile = fopen("encrypted.pdf", "rb");
    if (encryptedFile == NULL) {
        printf("Encryped file not exits!\n");
        exit(0);
    }
    fseek(encryptedFile, 0, SEEK_END);
    encryptedLength = ftell(signedFile);
    rewind(encryptedFile);
    encryptedBuffer = (unsigned char *)malloc(sizeof(char) * encryptedLength);
    if (encryptedBuffer == NULL) {
        printf("Memory Error!\n");
        exit(0);
    }
    if (fread(encryptedBuffer, 1, encryptedLength, encryptedFile) != encryptedLength) {
        printf("Encrypted File load error!\n");
        exit(0);
    }
    fclose(encryptedFile);
    
    FILE *decryptedFile = fopen("decrypted.pdf", "wb");
    if (decryptedFile == NULL) {
        printf("Create decrypted file error!\n");
        exit(0);
    }
    
    //save the uncrypted data to file
    char *tt;
    unsigned int length2;
    i = 0;
    while (i < encryptedLength) {
        int y = rsa->myDecrypt((unsigned char *)encryptedBuffer + i, 128, (unsigned char **)&tt, length2);
        //去除空格
        if (i + 128 >= encryptedLength) {
            y = 100;
            while (tt[y - 1] == 0) {
                y --;
                if (y == 0) {
                    break ;
                }
            }
        }
        fwrite(tt, 1, y, decryptedFile);
        free(tt);
        i += 128;
    }
    fclose(decryptedFile);
    
    
    //提取最后128位的签名
    decryptedFile = fopen("decrypted.pdf", "rb");
    fseek(decryptedFile, 0, SEEK_END);
    int decryptedFileSize = ftell(decryptedFile);
    rewind(decryptedFile);
    unsigned char *buffer = (unsigned char *)malloc(sizeof(char) * decryptedFileSize);
    if (fread(buffer, 1, decryptedFileSize, decryptedFile) != decryptedFileSize) {
        printf("File load error!\n");
        exit(0);
    }
    fclose(decryptedFile);
    printf("解密成功，长度为%d\n", decryptedFileSize);
    
    printf("验证签名中…\n");

    //验证
    int res = rsa->myVerify(buffer + decryptedFileSize - 128, 128, originalBuffer, originalSize);
    if (res == 1) {
        printf("验证成功!");
    }

    return 0;
}
