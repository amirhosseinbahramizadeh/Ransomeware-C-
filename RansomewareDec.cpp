#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <string>

// Decrypt the message using the RSA private key
void decrypt_RSA(RSA * rsa, std::string private_key_string, std::string message) {
    // Convert the private key string to a BIGNUM
    BIGNUM * priv_key = BN_new();
    BN_hex2bn(&priv_key, private_key_string.c_str());

    // Create an RSA key with the provided modulus and exponent
    RSA_set0_key(rsa, rsa->n, priv_key, NULL);

    // Allocate memory for the decrypted message
    int buf_len = RSA_size(rsa);
    unsigned char * buf = new unsigned char[buf_len];

    // Decrypt the message
    RSA_private_decrypt(message.length(), (unsigned char *) message.c_str(), buf, rsa, RSA_PKCS1_PADDING);

    // Convert the decrypted message from bytes to a string
    std::string decrypted_message = std::string(reinterpret_cast<char *>(buf));

    // Print the decrypted message
    std::cout << "Decrypted message: " << decrypted_message << std::endl;
}

int main() {
    // Create an RSA key to use for decryption
    RSA * rsa = RSA_new();

    // Your existing code to set the RSA key modulus and exponent goes here

    // Call the decrypt_RSA function to decrypt the message
    decrypt_RSA(rsa, private_key_string, encrypted_message);

    // Free the memory allocated for the RSA key
    RSA_free(rsa);

    return 0;
}