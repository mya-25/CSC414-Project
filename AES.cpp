#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/err.h>
#include <cstring>
#include <iostream>
#include <fstream>
#include <sstream>


//Helper function to handle OpenSSL errors
void handleErrors() {
    ERR_print_errors_fp(stderr);
    abort();
}

//Function to decode Base64 content
unsigned char* base64_decode(const char* input, int length, int* out_len) {
    BIO* bio, * b64;
    unsigned char* buffer = (unsigned char*)malloc(length);
    memset(buffer, 0, length);

    bio = BIO_new_mem_buf((void*)input, length);
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_push(b64, bio);

    // Decode Base64
    *out_len = BIO_read(bio, buffer, length);
    BIO_free_all(bio);

    return buffer;
}

//Function to decrypt using AES-128-ECB
void aes128_ecb_decrypt(const unsigned char* ciphertext, const unsigned char* key, unsigned char* plaintext, int ciphertext_len) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    int len;
    int plaintext_len;

    if (!EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, NULL))
        handleErrors();

    if (!EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
        handleErrors();
    plaintext_len = len;

    if (!EVP_DecryptFinal_ex(ctx, plaintext + len, &len))
        handleErrors();
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
}

//Function to read file content
std::string readFile(const std::string& filePath) {
    std::ifstream file(filePath);
    std::stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main() {
    // Read the Base64-encoded encrypted content from the file named "7.txt"
    std::string base64_encoded_ciphertext = readFile("7.txt");

    // Decryption key ("YELLOW SUBMARINE")
    const unsigned char* key = (unsigned char*)"YELLOW SUBMARINE";  // 16-byte key for AES-128

    // Decode Base64 content
    int decoded_len;
    unsigned char* decoded_ciphertext = base64_decode(base64_encoded_ciphertext.c_str(), base64_encoded_ciphertext.length(), &decoded_len);

    // Prepare buffer for plaintext
    unsigned char plaintext[decoded_len + 1];  // Add +1 for null-terminator

    // Decrypt the decoded ciphertext
    aes128_ecb_decrypt(decoded_ciphertext, key, plaintext, decoded_len);

    // Null-terminate the plaintext for printing
    plaintext[decoded_len] = '\0';

    // Print decrypted plaintext
    std::cout << "Decrypted text: " << plaintext << std::endl;

    // Cleanup
    free(decoded_ciphertext);

    return 0;
}

