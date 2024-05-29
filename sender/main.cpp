#include "sender.h"

int main(int argc, const char* argv[]){
    const char* enc_type  = argv[1];
    const char* sha_en = argv[2];
    const char* filepath = argv[3];
    bool sha = (strcmp(sha_en,"1") == 0);
    int serv_sock = getServerSocket("127.0.0.1", 8000);
    printf("Sender socket ready.\n");
    printf("Waiting for connection...\n");
    int clnt_sock=waitForConnection(serv_sock);
    printf("Connection built.\n");

    // receive seed.
    unsigned char seed[128];
    unsigned char *s_b=seed;
    recvSeed(s_b,128,clnt_sock);
    printf("The seed is %s\n", seed);

    // 生成密钥
     
    //  

    unsigned char fname[4097];
    unsigned char data_to_encrypt[8];
    unsigned char data_after_encrypt[8];
    unsigned char *dae;
    unsigned long fsize;

    FILE* fp;
    if((fp=fopen(filepath,"rb"))==NULL){
        printf("File error!\n");
    }
    printf("File opening...\n");

    fseek(fp,SEEK_SET,SEEK_END);
    fsize=ftell(fp);
    fseek(fp,0,SEEK_SET);
    memset(data_to_encrypt,0,sizeof(data_to_encrypt));
    if (strcmp(enc_type, "AES") == 0){
        AES_KEY AESEncryptKey = gen_aes_key((char *)seed);
        sendAESFile(fp,fsize,(unsigned char*)filepath,data_to_encrypt,data_after_encrypt,&AESEncryptKey,clnt_sock, sha);
    } else {
        DES_key_schedule key_schedule = gen_des_key((char *)seed);
        sendDESFile(fp, fsize, (unsigned char*)filepath, data_to_encrypt, data_after_encrypt, &key_schedule, clnt_sock, sha);
    }
    fclose(fp);
    close(serv_sock);
    return 0;
}
