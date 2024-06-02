#include "receiver.h"

int main(int argc, const char* argv[])
{
    const char* ex_method = argv[1];    // RSA or not
    const char* enc_type  = argv[2];    // AES or not
    const char* sha_en = argv[3];       // 1 or not
    bool sha = (strcmp(sha_en,"1") == 0);
    //get socket
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    //connect sender
    struct sockaddr_in serv_addr;
    memset(&serv_addr, 0, sizeof(serv_addr));
    serv_addr.sin_family = AF_INET;  //ipv4
    serv_addr.sin_addr.s_addr = inet_addr("127.0.0.1"); // ip address
    serv_addr.sin_port = htons(8000);  //port
    int result=connect(sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr));

    if(result==-1){
        printf("errno for connection is %d\n",errno);
    }else{
        printf("connection built!\n");
    }

    // send seed(由 RSA 和 DH 产生), 用于生成AES和DES密钥
    // RSA 先生成随机数，加密后传输给发送方
    // DH 不产生随机数，直接传输超大整数后在本地生成seed(密钥)
    unsigned char seed[128];
    if (strcmp(ex_method, "RSA") == 0)
        send_seed_RSA(seed, sock);
    else
        server_DH(seed, sock);
    printf("The seed is: ");
    for (int i = 0;i < 128;i++) { printf("0x%02x ", seed[i]); } puts("");

    unsigned char data_after_encrypt[16];
    unsigned char data_after_decrypt[16];

    //receive data
    printf("Waiting For File...\n");
    memset(data_after_encrypt,0,sizeof(data_after_encrypt));
    if (strcmp(enc_type, "AES") == 0){
        AES_KEY AESDecryptKey = gen_aes_key((char *)seed);
        recvAESFile(data_after_encrypt,data_after_decrypt,&AESDecryptKey, sock, sha);
    } else {
        DES_key_schedule key_schedule = gen_des_key((char *)seed);
        recvDESFile(data_after_encrypt, data_after_decrypt, &key_schedule, sock, sha);
    }
    close(sock);
    return 0;
}