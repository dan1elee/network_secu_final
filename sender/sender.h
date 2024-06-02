#ifndef SENDER_H_INCLUDED
#define SENDER_H_INCLUDED
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <errno.h>
#include <openssl/rsa.h>
#include <openssl/aes.h>
#include <openssl/des.h>
#include <openssl/sha.h>
#include <openssl/dh.h>

//sendKey: take rsa public key,public key length,client sock as inputs. Send rsa public key to receiver.
int sendKey(unsigned char *pk,int pk_len,int clnt_sock);
//sendData: take data after aes encryption, data length,client sock as inputs. Send data after aes encryption to receiver.
int sendData(unsigned char *data,int d_len,int clnt_sock);
//send file
int sendAESFile(FILE* fp,unsigned long fsize,unsigned char *path,unsigned char *data_to_encrypt,unsigned char *data_after_encrypt,AES_KEY *AESEncryptKey,int clnt_sock, bool sha_enable);
int sendDESFile(FILE *fp, unsigned long fsize, unsigned char *path, unsigned char *data_to_encrypt, unsigned char *data_after_encrypt, DES_key_schedule* des_key_schedule, int clnt_sock,bool sha_enable);
//recvSeed: take buffer, length of the data to receive, client sock as inputs. Receive seed to generate aes key from receiver.
int recvSeed(unsigned char *buffer,int s_len,int clnt_sock);
//create server socket.
int getServerSocket(const char *ip,int port);
//waiting for connection from receiver.
int waitForConnection(int serv_sock);
double getTime();
AES_KEY gen_aes_key(char seed[]);
DES_key_schedule gen_des_key(char seed[]);
int fileSHA256(FILE* fp, unsigned long fsize, unsigned char* hash);

// Use RSA to receive the AES/DES seed. At file sender side.
void recv_seed_RSA(unsigned char *seed, int clnt_sock);

// Use DH to exchange seed.
void client_DH(unsigned char *seed, int sock);

#endif // SENDER_H_INCLUDED
