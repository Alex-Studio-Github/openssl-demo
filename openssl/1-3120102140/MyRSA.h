//
//  MyRSA.h
//  openssl
//
//  Created by Xinbao Dong on 15/4/5.
//  Copyright (c) 2015年 com.dongxinbao. All rights reserved.
//

#ifndef __openssl__MyRSA__
#define __openssl__MyRSA__

#include <stdio.h>
#include "Key.h"

class MyRSA {
public:
    Key *key;
    MyRSA(Key *key);
    int myEncrypt(const unsigned char *plain, int length, unsigned char **cipher, unsigned int &r_length);
    int myDecrypt(const unsigned char *cipher, int length, unsigned char **plain, unsigned int &r_length);
    
    int mySign(const unsigned char *plain, int length, unsigned char **cipher, unsigned int &r_length);
    int myVerify(const unsigned char *cipher, int length, unsigned char *plain, int plainLength);
//    char *mySign(char *content, int length);
//    char *myVerify(char *content, int length);
//    
//    char *base64encode(const unsigned char *inputBuffer, int inputLen);
};

#endif /* defined(__openssl__MyRSA__) */
