#include "sender.h"

int main(int argc, const char* argv[]) {
    const char* ex_method = argv[1];    // RSA or not
    const char* enc_type  = argv[2];    // AES or not
    const char* sha_en = argv[3];       // 1 or not
    const char* filepath = argv[4];     // file path
    bool sha = (strcmp(sha_en, "1") == 0);
    int serv_sock = getServerSocket("127.0.0.1", 8000);
    printf("Sender socket ready.\n");
    printf("Waiting for connection...\n");
    int clnt_sock = waitForConnection(serv_sock);
    printf("Connection built.\n");

    // receive seed.
    unsigned char seed[128];
    if (strcmp(ex_method, "RSA") == 0)
        recv_seed_RSA(seed, clnt_sock);
    else
        client_DH(seed, clnt_sock);
    printf("The seed is: ");
    for (int i = 0;i < 128;i++) { printf("0x%02x ", seed[i]); } puts("");

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
