//
//  Key.h
//  openssl
//
//  Created by Xinbao Dong on 15/4/4.
//  Copyright (c) 2015年 com.dongxinbao. All rights reserved.
//

#ifndef __openssl__Key__
#define __openssl__Key__

#include <stdio.h>
#include <string>
#include <openssl/rsa.h>

using namespace std;

class Key {
public:
    RSA *rsa;
    RSA *privateKey;
    RSA *publicKey;
    Key() {rsa = privateKey = publicKey = NULL;};
    Key(string publicKeyFile, string privateKeyFile);
    ~Key();
    void generateNewKey(string publicKeyFile, string privateKeyFile);
    void reload();
    
private:
    string priName;
    string pubName;
};

#endif /* defined(__openssl__Key__) */
