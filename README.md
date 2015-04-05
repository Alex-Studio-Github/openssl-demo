# openssl-demo
A demo of openssl encrypt &amp; decrypt using RSA, signature &amp; verify using sha1. The demo simulate the complete process of signature-encrypt-decrypt-verify.

这是网络安全课程的某次作业，作业要求是利用openssl库模拟签名、加密、解密、验证签名的整个过程，理解公私钥的具体用法。

* Language: C++
* 该demo用了SHA1和私钥进行签名，签名结果附在文件最后。
* 采用RSA算法进行加密，每100字节加密一次。（可自定义，需要注意padding为RSA_PKCS1_PADDING时需要留出11个字节的空间，也就是最多117）
