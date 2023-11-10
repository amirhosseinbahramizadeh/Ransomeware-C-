#include <iostream>
#include <string>
#include <sstream>
#include <vector>
#include <ctime>
#include <random>
#include <chrono>
#include <algorithm>
#include <bitset>
#include <cstdlib>
#include <ctime>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/ec.h>
#include <openssl/bn.h>

#define RSA_KEY_SIZE 2048

typedef struct rsa_st RSA;
typedef struct bignum_st BIGNUM;

void init_RSA(RSA ** rsa, BIGNUM ** e);
void RSA_to_public_key(RSA * rsa, char * key);
void encrypt_RSA(RSA * rsa, char * key, char * message);
void generate_random_number(BIGNUM * num, int length);

void create_wallet(std::string & priv_key, std::string & pub_key) {
    BIGNUM * e = BN_new();
    RSA * rsa = RSA_new();

    BN_set_word(e, RSA_F4);
    generate_random_number(e, 3);

    init_RSA(&rsa, &e);
    RSA_to_public_key(rsa, pub_key);

    BN_bn2hex(rsa->d, priv_key);

    RSA_free(rsa);
    BN_free(e);
}

void init_RSA(RSA ** rsa, BIGNUM ** e) {
    *rsa = RSA_new();
    *e = BN_new();

    BN_set_word(*e, RSA_F4);
    generate_random_number(*e, 3);

    RSA_generate_key_ex(*rsa, RSA_KEY_SIZE, *e, NULL);
}

void RSA_to_public_key(RSA * rsa, char * key) {
    BIO * bio = BIO_new(BIO_s_mem());
    PEM_write_bio_RSAPublicKey(bio, rsa);

    int key_size = BIO_pending(bio);
    key = new char[key_size + 1];
    BIO_read(bio, key, key_size);
    key[key_size] = '\0';

    BIO_free(bio);
}

void encrypt_RSA(RSA * rsa, char * key, char * message) {
    BIO * bio = BIO_new_mem_buf(key, -1);
    EVP_PKEY * pkey = PEM_read_bio_PUBKEY(bio, NULL, NULL, NULL);

    size_t buf_len = RSA_size(rsa);
    unsigned char * buf = new unsigned char[buf_len];

    EVP_PKEY_encrypt_init(pkey);
    EVP_PKEY_CTX * ctx = EVP_PKEY_CTX_new(pkey, NULL);
    EVP_PKEY_encrypt(ctx, buf, &buf_len, (unsigned char *) message, strlen(message));

    EVP_PKEY_CTX_free(ctx);
    EVP_PKEY_free(pkey);
    BIO_free(bio);

    std::cout << "Encrypted message: " << buf << std::endl;
}

void generate_random_number(BIGNUM * num, int length) {
    RAND_load_file("/dev/urandom", length);
    BN_rand(num, length, 0, 0);
}

int main() {
    std::string private_key, public_key;
    create_wallet(private_key, public_key);

    std::cout << "Private key: " << private_key << std::endl;
    std::cout << "Public key: " << public_key << std::endl;

    RSA * rsa = RSA_new();
    BIO * bio = BIO_new_mem_buf(public_key.c_str(), -1);
    PEM_read_bio_RSAPublicKey(bio, &rsa, NULL, NULL);

    char * message = "Hello, world!";
    encrypt_RSA(rsa, public_key.c_str(), message);

    RSA_free(rsa);
    BIO_free(bio);

    return 0;
}