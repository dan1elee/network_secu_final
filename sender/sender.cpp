#include "sender.h"
#define SHA_BUFFER_SIZE 32
int getServerSocket(const char *ip,int port){
    int serv_sock=socket(AF_INET,SOCK_STREAM,0);
    if(serv_sock!=-1){
        int opt = 1;
        setsockopt(serv_sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));//for checking
        struct sockaddr_in serv_addr;
        memset(&serv_addr, 0, sizeof(serv_addr));
        serv_addr.sin_family = AF_INET;  //ipv4
        serv_addr.sin_addr.s_addr = inet_addr(ip);  //ip address
        serv_addr.sin_port = htons(port);  //port
        if(bind(serv_sock, (struct sockaddr*)&serv_addr, sizeof(serv_addr))!=-1){
            listen(serv_sock,20);
            return serv_sock;
        }else{
            printf("errno for bind() in getServerSocket is %d\n",errno);
            printf("ending the program!\n");
            exit(0);
        }
    }else{
        printf("errno for socket() in getServerSocket is %d\n",errno);
        printf("ending the program!\n");
        exit(0);
    }
    return -1;
}

int waitForConnection(int serv_sock){
    struct sockaddr_in clnt_addr;
    socklen_t clnt_addr_size = sizeof(clnt_addr);
    int clnt_sock = accept(serv_sock, (struct sockaddr*)&clnt_addr, &clnt_addr_size);
    if(clnt_sock!=-1){
        return clnt_sock;
    }else{
        printf("errno for waitForConnection is %d\n",errno);
        printf("ending the program!\n");
        exit(0);
    }
    return -1;
}

int sendKey(unsigned char *pk,int pk_len,int clnt_sock){
    //transfer integer
    int32_t conv=htonl(pk_len);
    char *data = (char*)&conv;
    int len = sizeof(conv);
    char *key=(char*)pk;
    //rc1 and rc2 stands for how much data sent this round
    int rc1;
    do{
        rc1=write(clnt_sock, data, len);
        if(rc1<0){
            printf("errno while sending public key length is %d\n",errno);
            exit(0);
        }else{
            data+=rc1;
            len-=rc1;
        }
    }while(len>0);

    int rc2;
    do{
        rc2=write(clnt_sock, key, pk_len);
        if(rc2<0){
            printf("errno while sending public key is %d\n",errno);
            exit(0);
        }else{
            key+=rc2;
            pk_len-=rc2;
        }
    }while(pk_len>0);
    return 0;
}

int sendData(unsigned char *data,int d_len,int clnt_sock){
    int rc;
    int len=d_len;
    do{
        rc=write(clnt_sock, data, len);
        if(rc<0){
            printf("errno while sending encrypted data is %d\n",errno);
            exit(0);
        }else{
            data+=rc;
            len-=rc;
        }

    }while(len>0);
    return len;
}

int recvData(unsigned char *data, int len, int clnt_sock){
    int r;

    do {
        r = read(clnt_sock, data, len);
        if(r < 0) {
            printf("errno while receive seed is %d\n",errno);
            exit(0);
        } else {
            data += r;
            len  -= r;
        }
    } while(len>0);
    
    return len;
}

AES_KEY gen_aes_key(char seed[])
{
    for(int i=0;i<128;++i){
        printf("0x%02x ", seed[i]);
    }
    printf("\n");
    // // AES密钥生成
    unsigned char aesSeed[32];
    strncpy((char *)aesSeed, (const char *)seed, 32);
    AES_KEY AESEncryptKey;
    int key_len = 256;
    AES_set_encrypt_key(aesSeed, key_len, &AESEncryptKey);
    return AESEncryptKey;
}

DES_key_schedule gen_des_key(char seed[])
{
    DES_cblock key;
    DES_key_schedule key_schedule;
    // unsigned char desSeed[32];
    // strncpy((char *)desSeed, (const char *)seed, 32);
    // DES密钥生成
    DES_string_to_key((const char *)seed, &key);
    // 判断生成key_schedule是否成功
    if (DES_set_key_checked(&key, &key_schedule) != 0)
    {
        printf("key_schedule failed.\n");
    }
    return key_schedule;
}

int sendAESFile(FILE* fp,unsigned long fsize,unsigned char *path,unsigned char *data_to_encrypt,unsigned char *data_after_encrypt,AES_KEY *AESEncryptKey,int clnt_sock, bool sha_enable){
    //send file size
    unsigned long times=((unsigned long)(fsize/16))+1;
    printf("File size:%lu bytes\n",fsize);
    char* fs=(char*)&fsize;
    char p_fs[16];//padding to 16bytes
    memset(p_fs,0,sizeof(p_fs));
    strncpy(p_fs,(const char*)fs,sizeof(fs));
    char e_fs[16];
    AES_encrypt((unsigned char*)p_fs, (unsigned char*)e_fs, AESEncryptKey);
    sendData((unsigned char*)e_fs,sizeof(e_fs),clnt_sock);
    //send file name
    const char ch='/';
    const char *ret;
    ret=strrchr((const char*)path,ch);
    char fn[256];
    memset(fn,0,sizeof(fn));
    if(ret!=NULL){
        strcpy(fn,(const char*)ret+1);
    }else{
        strcpy(fn,(const char*)path);
    }
    printf("File name:%s\n",fn);
    char e_fn[256];
    AES_encrypt((unsigned char*)fn, (unsigned char*)e_fn, AESEncryptKey);
    sendData((unsigned char*)e_fn,sizeof(e_fn),clnt_sock);
    //send data
    printf("Sending File...\n");
    double en_time = 0.0;
    for (unsigned long i = 0; i < times; i++)
    {
        fread(data_to_encrypt,16,1,fp);
        double time3 = getTime();
        AES_encrypt(data_to_encrypt, data_after_encrypt, AESEncryptKey);
        double time4 = getTime();
        sendData(data_after_encrypt,16,clnt_sock);
        en_time += time4 - time3;
    }
    printf("%lu bytes加密时间: %.2f ms\n", fsize, en_time);
    if(sha_enable){
        unsigned char hash[SHA256_DIGEST_LENGTH];
        fileSHA256(fp, fsize, hash);

        unsigned char hash16[16];
        unsigned char hash16_encrypt[16];
        memcpy(hash16,hash,16);
        AES_encrypt(hash16,hash16_encrypt,AESEncryptKey);
        sendData(hash16_encrypt, 16, clnt_sock);

        memcpy(hash16,hash+16,16);
        AES_encrypt(hash16,hash16_encrypt,AESEncryptKey);
        sendData(hash16_encrypt, 16, clnt_sock);
    }
    printf("Completes!\n");
    return 0;
}

int sendDESFile(FILE *fp, unsigned long fsize, unsigned char *path, unsigned char *data_to_encrypt, unsigned char *data_after_encrypt, DES_key_schedule *des_key_schedule, int clnt_sock, bool sha_enable)
{
    // send file size
    unsigned long times = ((unsigned long)(fsize / 8)) + 1;
    printf("File size:%lu bytes\n", fsize);
    char *fs = (char *)&fsize;
    char p_fs[8]; // padding to 8bytes
    memset(p_fs, 0, sizeof(p_fs));
    strncpy(p_fs, (const char *)fs, sizeof(fs));
    char e_fs[8];
    DES_ecb_encrypt((DES_cblock *)p_fs, (DES_cblock *)e_fs, des_key_schedule, DES_ENCRYPT);
    sendData((unsigned char *)e_fs, sizeof(e_fs), clnt_sock);
    // send file name
    const char ch = '/';
    const char *ret;
    ret = strrchr((const char *)path, ch);
    char fn[256];
    memset(fn, 0, sizeof(fn));
    if (ret != NULL)
    {
        strcpy(fn, (const char *)ret + 1);
    }
    else
    {
        strcpy(fn, (const char *)path);
    }
    printf("File name:%s\n", fn);
    char e_fn[256];
    DES_ecb_encrypt((DES_cblock *)fn, (DES_cblock *)e_fn, des_key_schedule, DES_ENCRYPT);
    sendData((unsigned char *)e_fn, sizeof(e_fn), clnt_sock);
    // send data
    printf("Sending File...\n");
    double en_time = 0.0;
    for (unsigned long i = 0; i < times; i++)
    {
        fread(data_to_encrypt, 8, 1, fp);
        double time3 = getTime();
        DES_ecb_encrypt((DES_cblock *)data_to_encrypt, (DES_cblock *)data_after_encrypt,des_key_schedule, DES_ENCRYPT);
        double time4 = getTime();
        sendData(data_after_encrypt, 8, clnt_sock);
        en_time += time4 - time3;
    }
    printf("%lu bytes加密时间: %.2f ms\n", fsize, en_time);
    if (sha_enable){
        unsigned char hash[SHA256_DIGEST_LENGTH];
        fileSHA256(fp, fsize, hash);
        
        
        unsigned char hash8[8];
        unsigned char hash8_encrypt[8];
        memcpy(hash8,hash,8);
        DES_ecb_encrypt((DES_cblock *)hash8, (DES_cblock *)hash8_encrypt,des_key_schedule, DES_ENCRYPT);
        sendData(hash8_encrypt, 8, clnt_sock);

        memcpy(hash8,hash+8,8);
        DES_ecb_encrypt((DES_cblock *)hash8, (DES_cblock *)hash8_encrypt,des_key_schedule, DES_ENCRYPT);
        sendData(hash8_encrypt, 8, clnt_sock);

        memcpy(hash8,hash+16,8);
        DES_ecb_encrypt((DES_cblock *)hash8, (DES_cblock *)hash8_encrypt,des_key_schedule, DES_ENCRYPT);
        sendData(hash8_encrypt, 8, clnt_sock);

        memcpy(hash8,hash+24,8);
        DES_ecb_encrypt((DES_cblock *)hash8, (DES_cblock *)hash8_encrypt,des_key_schedule, DES_ENCRYPT);
        sendData(hash8_encrypt, 8, clnt_sock);
    }

    printf("Completes!\n");
    return 0;
}

double getTime(){
    clock_t ticks = clock();
    return (ticks * 1000.0) / CLOCKS_PER_SEC;
}

int fileSHA256(FILE* fp, unsigned long fsize, unsigned char* hash){
    fseek(fp, 0, SEEK_SET);
    unsigned char buffer[SHA_BUFFER_SIZE];
    size_t bytes_read;
    SHA256_CTX sha256;
    SHA256_Init(&sha256);
    unsigned long times=((unsigned long)(fsize/sizeof(buffer)))+1;
    for(unsigned long i=0;i<times;i++){
        bytes_read = fread(buffer, sizeof(char), sizeof(buffer), fp);
        SHA256_Update(&sha256, buffer, bytes_read);
    }
    SHA256_Final(hash, &sha256);
    printf("File SHA256:");
    for(int i=0;i<32;++i){
        printf(" 0x%0x",hash[i]);
    }
    printf("\n");
    return 0;
}

void recv_seed_RSA(unsigned char *seed, int clnt_sock) {
    // Gen 1024-bits RSA key
    RSA *rsa_key = RSA_generate_key(1024, RSA_F4, NULL, NULL);

    // print the rsa.
    // RSA_print_fp(stdout, rsa_key, 0);
    
    // Extract the public key information. 
    // Change the data structure of the RSA key for transforming.
    unsigned char *public_key = NULL;
    int public_key_len = i2d_RSAPublicKey(rsa_key, &public_key);

    // print public key length
    printf("length of public key: %d\n", public_key_len);
    // print public key information for comparison
    printf("public key: \n");
    for (int i = 0;i < public_key_len;i++) { printf("0x%02x ", public_key[i]); }
    printf("\n\n");

    // send public key information and key length to receiver.
    sendKey(public_key, public_key_len, clnt_sock);

    // receive the encrypted AES/DES seed
    unsigned char seed_after_encrypt[128];
    recvData(seed_after_encrypt, 128, clnt_sock);

    // decrypt the seed. // be careful about SIGSEGV
    memset(seed, 0, 128);
    RSA_private_decrypt(128, (const unsigned char*) seed_after_encrypt, seed, rsa_key, RSA_NO_PADDING);
}

void client_DH(unsigned char *seed, int sock) {
    DH *dh = DH_new();
    int net_len;

    // Receive DH parameters from the server
    unsigned char p_bin[1024], g_bin[1024];
    int p_len, g_len;
    // Receive the length of the data first
    if (read(sock, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        perror("Failed to receive data length");
        exit(EXIT_FAILURE);
    }
    p_len = ntohl(net_len); // Convert length from network byte order to host byte order
    recvData(p_bin, p_len, sock);
    // Receive the length of the data first
    if (read(sock, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        perror("Failed to receive data length");
        exit(EXIT_FAILURE);
    }
    g_len = ntohl(net_len); // Convert length from network byte order to host byte order
    recvData(g_bin, g_len, sock);

    BIGNUM *p = BN_bin2bn(p_bin, p_len, NULL);
    BIGNUM *g = BN_bin2bn(g_bin, g_len, NULL);

    // Set DH parameters (client side)
    DH_set0_pqg(dh, p, NULL, g);

    // Generate DH key pair (client side)
    if (1 != DH_generate_key(dh)) {
        printf("DH key generation failed\n");
        return;
    }

    // Receive the server's public key
    unsigned char server_pub_key_bin[1024];
    int server_pub_key_len;
    // Receive the length of the data first
    if (read(sock, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        perror("Failed to receive data length");
        exit(EXIT_FAILURE);
    }
    server_pub_key_len = ntohl(net_len); // Convert length from network byte order to host byte order
    recvData(server_pub_key_bin, server_pub_key_len, sock);

    // Send public key to the server
    const BIGNUM *pub_key = DH_get0_pub_key(dh);
    int pub_key_len = BN_num_bytes(pub_key);
    unsigned char *pub_key_bin = (unsigned char *)malloc(pub_key_len);
    BN_bn2bin(pub_key, pub_key_bin);
    // Send the length of the data first
    net_len = htonl(pub_key_len); // Convert length to network byte order
    if (write(sock, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        perror("Failed to send data length");
        exit(EXIT_FAILURE);
    }
    sendData(pub_key_bin, pub_key_len, sock);

    BIGNUM *server_pub_key = BN_bin2bn(server_pub_key_bin, server_pub_key_len, NULL);

    // Compute the shared secret
    unsigned char shared_secret[1024];
    int secret_size = DH_compute_key(shared_secret, server_pub_key, dh);
    if (secret_size < 0) {
        printf("Failed to compute shared secret\n");
        return;
    }

    // Derive the seed from the shared secret
    memcpy(seed, shared_secret, secret_size);
    seed[secret_size] = 0;

    printf("The shared secret (seed) is: ");
    for (int i = 0; i < secret_size; i++) {
        printf("0x%02x ", seed[i]);
    }
    printf("\n");

    free(pub_key_bin);
    DH_free(dh);
    BN_free(server_pub_key);
}
