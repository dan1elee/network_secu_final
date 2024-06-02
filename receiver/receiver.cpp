#include "receiver.h"
#define SHA_BUFFER_SIZE 32

int sendData(unsigned char *data, int len, int sock){
    int r;
    do {
        r = write(sock, data, len);
        if(r < 0) {
            printf("errno while sending seed is %d\n", errno);
            exit(0);
        } else {
            data += r;
            len  -= r;
        }
    } while(len > 0);
    
    return len;
}

int recvData(unsigned char *data, int len, int clnt_sock){
    int r;

    do {
        r = read(clnt_sock, data, len);
        if(r < 0) {
            printf("errno while receive seed is %d\n", errno);
            exit(0);
        } else {
            data += r;
            len  -= r;
        }
    } while(len > 0);
    
    return len;
}

int recvEncryptedData(unsigned char *dae,int d_len,int sock){
    int rc;
    int len=d_len;
    do{
        rc=read(sock, dae, len);
        if(rc<0){
            printf("errno while receiving encrypted data is %d\n",errno);
            exit(0);
        }else{
            dae+=rc;
            len-=rc;
        }
    }while(len>0);
    return 0;

}

int recvPKeyAndLen(unsigned char *b_f, int32_t *pk_len,int sock){
    int left1=sizeof(*pk_len);
    int left2=0;
    char *data=(char*)pk_len;
    int rc1;
    int rc2;
    do{
        rc1=read(sock, data, left1);
        if(rc1<0){
            printf("errno while receiving public key length is %d\n",errno);
            exit(0);
        }else{
            data+=rc1;
            left1-=rc1;
        }
    }while(left1>0);


    left2=ntohl(*pk_len);
    do{
        rc2=read(sock, b_f, left2);
        if(rc2<0){
            printf("errno while receiving public key is %d\n",errno);
            exit(0);
        }else{
            b_f+=rc2;
            left2-=rc2;
        }
    }while(left2>0);
    return 0;
}

int genSeed(unsigned char* ranstr){
    int i,flag;
    srand(time(NULL));
    for(i = 0; i < SEED_LEN-1; i ++)
    {
		flag = rand()%3;
		switch(flag)
		{
		case 0:
			*(ranstr+i) = rand()%26 + 'a';
			break;
		case 1:
			*(ranstr+i) = rand()%26 + 'A';
			break;
		case 2:
			*(ranstr+i) = rand()%10 + '0';
			break;
		}
    }
    return i;
}

AES_KEY gen_aes_key(char seed[]){
    // // AES密钥生成
    for(int i=0;i<128;++i){
        printf("0x%02x ", seed[i]);
    }
    printf("\n");
    unsigned char aesSeed[32];
    strncpy((char *)aesSeed, (const char *)seed, 32);
    AES_KEY AESDecryptKey;
    int key_len = 256;
    AES_set_decrypt_key(aesSeed, key_len, &AESDecryptKey);
    return AESDecryptKey;
}

DES_key_schedule gen_des_key(char seed[]) {
    DES_cblock key;
    DES_key_schedule key_schedule;
    // unsigned char desSeed[32];
    // strncpy((char *)desSeed, (const char *)seed, 32);
    // DES密钥生成
    DES_string_to_key((const char*) seed,  &key);
    // 判断生成key_schedule是否成功
    if (DES_set_key_checked(&key, &key_schedule) != 0)
    {
        printf("key_schedule failed.\n");
    }
    return key_schedule;
}

int recvAESFile(unsigned char *data_after_encrypt,unsigned char *data_after_decrypt,AES_KEY *AESDecryptKey,int sock, bool sha_enable){
    unsigned long fsize=0;
    char fs[8];
    char p_fs[16];
    char d_fs[16];
    double time1 = getTime();
    recvEncryptedData((unsigned char*)p_fs,sizeof(p_fs),sock);
    AES_decrypt((unsigned char*)p_fs, (unsigned char*)d_fs, AESDecryptKey);
    strncpy(fs,(const char*)d_fs,8);
    fsize=*((unsigned long*)fs);
    printf("File size:%lu\n",fsize);
    unsigned long times=((unsigned long)(fsize/16))+1;
    char fn[256];
    memset(fn,0,sizeof(fn));
    char e_fn[256];
    memset(e_fn,0,sizeof(e_fn));
    recvEncryptedData((unsigned char*)e_fn,sizeof(e_fn),sock);
    AES_decrypt((unsigned char*)e_fn, (unsigned char*)fn, AESDecryptKey);
    printf("File name:%s\n",fn);
    FILE *fp;
    if((fp=fopen((const char*)fn,"wb"))==NULL){
        printf("File error!\nEnding the program!\n");
        exit(0);
    }
    printf("Writing file...\n");
    double de_time = 0.0;
    for(int i=0;i<times;i++){
        recvEncryptedData(data_after_encrypt,16,sock);
        double time3 = getTime();
        AES_decrypt(data_after_encrypt, data_after_decrypt, AESDecryptKey);
        double time4 = getTime();
        if(i!=times-1){
            fwrite(data_after_decrypt,16,1,fp);
        }else{
            fwrite(data_after_decrypt,fsize%16,1,fp);
        }
        de_time += time4 - time3;
    }
    fclose(fp);
    double time2 = getTime();
    printf("文件长度:%lu bytes，文件解密时间:%.2f ms，文件传输总时间: %.2f ms\n", fsize, de_time , time2-time1);
    
    if (sha_enable){
        unsigned char recvHash_encrypt[16];
        unsigned char recvHash[SHA256_DIGEST_LENGTH];
        recvEncryptedData(recvHash_encrypt, 16, sock);
        AES_decrypt(recvHash_encrypt,recvHash, AESDecryptKey);

        recvEncryptedData(recvHash_encrypt, 16, sock);
        AES_decrypt(recvHash_encrypt,recvHash+16, AESDecryptKey);

        fp=fopen((const char*)fn, "rb");
        unsigned char hash[SHA256_DIGEST_LENGTH];
        fileSHA256(fp,fsize,hash);
        int cmpResult = memcmp(recvHash, hash, SHA256_DIGEST_LENGTH);
        if (cmpResult == 0){
            printf("SHA-256 match\n");
        } else {
            printf("SHA-256 not match\n");
        }
    }
    printf("Completes!\n");
}

int recvDESFile(unsigned char *data_after_encrypt, unsigned char *data_after_decrypt, DES_key_schedule *des_key_schedule, int sock, bool sha_enable)
{
    unsigned long fsize = 0;
    char fs[8];
    unsigned char p_fs[8];
    unsigned char d_fs[8];
    double time1 = getTime();
    recvEncryptedData((unsigned char *)p_fs, sizeof(p_fs), sock);
    DES_ecb_encrypt((DES_cblock *)p_fs, (DES_cblock *)d_fs, des_key_schedule, DES_DECRYPT);
    strncpy(fs, (const char *)d_fs, 8);
    fsize = *((unsigned long *)fs);
    printf("File size:%lu\n", fsize);
    unsigned long times = ((unsigned long)(fsize / 8)) + 1;
    char fn[256];
    memset(fn, 0, sizeof(fn));
    char e_fn[256];
    memset(e_fn, 0, sizeof(e_fn));
    recvEncryptedData((unsigned char *)e_fn, sizeof(e_fn), sock);
    DES_ecb_encrypt((DES_cblock *)e_fn, (DES_cblock *)fn, des_key_schedule, DES_DECRYPT);
    printf("File name:%s\n", fn);
    FILE *fp;
    if ((fp = fopen((const char *)fn, "wb")) == NULL)
    {
        printf("File error!\nEnding the program!\n");
        exit(0);
    }
    printf("Writing file...\n");
    double de_time = 0.0;
    for (int i = 0; i < times; i++)
    {
        recvEncryptedData(data_after_encrypt, 8, sock);
        double time3 = getTime();
        DES_ecb_encrypt((DES_cblock *)data_after_encrypt, (DES_cblock *)data_after_decrypt, des_key_schedule, DES_DECRYPT);
        double time4 = getTime();
        if (i != times - 1)
        {
            fwrite(data_after_decrypt, 8, 1, fp);
        }
        else
        {
            fwrite(data_after_decrypt, fsize % 8, 1, fp);
        }
        de_time += time4 - time3;
    }
    fclose(fp);
    double time2 = getTime();
    printf("文件长度:%lu bytes，文件解密时间:%.2f ms，文件传输总时间: %.2f ms\n", fsize, de_time, time2 - time1);
    if (sha_enable){
        unsigned char recvHash_encrypt[8];
        unsigned char recvHash[SHA256_DIGEST_LENGTH];
        recvEncryptedData(recvHash_encrypt, 8, sock);
        DES_ecb_encrypt((DES_cblock *)recvHash_encrypt, (DES_cblock *)recvHash, des_key_schedule, DES_DECRYPT);
        
        recvEncryptedData(recvHash_encrypt, 8, sock);
        DES_ecb_encrypt((DES_cblock *)recvHash_encrypt, (DES_cblock *)(recvHash+8), des_key_schedule, DES_DECRYPT);
        
        recvEncryptedData(recvHash_encrypt, 8, sock);
        DES_ecb_encrypt((DES_cblock *)recvHash_encrypt, (DES_cblock *)(recvHash+16), des_key_schedule, DES_DECRYPT);
        
        recvEncryptedData(recvHash_encrypt, 8, sock);
        DES_ecb_encrypt((DES_cblock *)recvHash_encrypt, (DES_cblock *)(recvHash+24), des_key_schedule, DES_DECRYPT);
        
        fp=fopen((const char*)fn, "rb");
        unsigned char hash[SHA256_DIGEST_LENGTH];
        fileSHA256(fp,fsize,hash);
        int cmpResult = memcmp(recvHash, hash, SHA256_DIGEST_LENGTH);
        if (cmpResult == 0){
            printf("SHA-256 match\n");
        } else {
            printf("SHA-256 not match\n");
        }
    }
    printf("Completes!\n");
}

double getTime() {
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

void send_seed_RSA(unsigned char *seed, int sock) {
    unsigned char public_key[1024];
    int public_key_len;
    recvPKeyAndLen(public_key, &public_key_len, sock);

    // print public key information for comparison
    for (int i = 0;i < ntohl(public_key_len);i++) { printf("0x%02x ", public_key[i]); }
    printf("\npublic ket len from server:%d\n\n", ntohl(public_key_len));

    // switch RSA key's data structure for decrypting.
    unsigned char *public_key_ptr = public_key;
    RSA *rsa = d2i_RSAPublicKey(NULL, (const unsigned char**)&public_key_ptr, ntohl(public_key_len));
    if(rsa == NULL){
        printf("switch rsa data structure failed!\n");
    }
    // RSA_print_fp(stdout, rsa, 0);

    //encrypt process
    unsigned char seed_after_encrypt[128];
    memset(seed, 0, 128);
    genSeed(seed);
    
    if(RSA_public_encrypt(128, (const unsigned char*)seed, seed_after_encrypt, rsa, RSA_NO_PADDING) == -1) {
        printf("encrypt failed!\n");
        char szErrMsg[1024] = {0};
        printf("error for encrypt is %s\n", ERR_error_string(ERR_get_error(), szErrMsg));
    } else {
        printf("The seed is");
        for (int i = 0;i < 128;i++) {
            printf(" 0x%02x", seed[i]);
        }
        printf("\n\n");
        printf("The seed after encryption is: ");
        for (int i = 0;i < 128;i++) {
            printf(" 0x%02x", seed_after_encrypt[i]);
        }
        printf("\n\n");
    }

    //send encrypted seed
    sendData(seed_after_encrypt, 128, sock);
}


void server_DH(unsigned char *seed, int sock) {
    DH *dh = DH_new();
    int codes;
    int net_len;

    // Generate DH parameters (server side)
    if (1 != DH_generate_parameters_ex(dh, 1024, DH_GENERATOR_2, NULL)) {
        printf("DH parameter generation failed\n");
        return;
    }

    if (1 != DH_check(dh, &codes) || codes != 0) {
        printf("DH parameter check failed\n");
        return;
    }

    // Send DH parameters to the client
    const BIGNUM *p = DH_get0_p(dh);
    const BIGNUM *g = DH_get0_g(dh);

    int p_len = BN_num_bytes(p);
    int g_len = BN_num_bytes(g);
    
    unsigned char *p_bin = (unsigned char *)malloc(p_len);
    unsigned char *g_bin = (unsigned char *)malloc(g_len);

    BN_bn2bin(p, p_bin);
    BN_bn2bin(g, g_bin);

    // Send the length of the data first
    net_len = htonl(p_len); // Convert length to network byte order
    if (write(sock, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        perror("Failed to send data length");
        exit(EXIT_FAILURE);
    }
    sendData(p_bin, p_len, sock);
    // Send the length of the data first
    net_len = htonl(g_len); // Convert length to network byte order
    if (write(sock, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        perror("Failed to send data length");
        exit(EXIT_FAILURE);
    }
    sendData(g_bin, g_len, sock);

    free(p_bin);
    free(g_bin);

    // Generate DH key pair (server side)
    if (1 != DH_generate_key(dh)) {
        printf("DH key generation failed\n");
        return;
    }

    const BIGNUM *pub_key = DH_get0_pub_key(dh);

    // Send public key to the client
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

    // Receive the client's public key
    unsigned char client_pub_key_bin[1024];
    int client_pub_key_len;
    // Receive the length of the data first
    if (read(sock, &net_len, sizeof(net_len)) != sizeof(net_len)) {
        perror("Failed to receive data length");
        exit(EXIT_FAILURE);
    }
    client_pub_key_len = ntohl(net_len); // Convert length from network byte order to host byte order
    recvData(client_pub_key_bin, client_pub_key_len, sock);

    BIGNUM *client_pub_key = BN_bin2bn(client_pub_key_bin, client_pub_key_len, NULL);

    // Compute the shared secret
    unsigned char shared_secret[1024];
    int secret_size = DH_compute_key(shared_secret, client_pub_key, dh);
    if (secret_size < 0) {
        printf("Failed to compute shared secret\n");
        return;
    }

    // Derive the seed from the shared secret
    memcpy(seed, shared_secret, secret_size);
    seed[secret_size] = 0;

    printf("The shared secret (seed) is: ");
    for (int i = 0; i < secret_size; i++) {
        printf("%02x", seed[i]);
    }
    printf("\n");

    free(pub_key_bin);
    DH_free(dh);
    BN_free(client_pub_key);
}