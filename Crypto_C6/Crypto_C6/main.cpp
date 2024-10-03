#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <stdexcept>
#include <cmath>
#include <map>
#include <algorithm>
#include <iterator>
#include <sstream>
#include <bitset>
#include <filesystem>


// Base64 decoding function
std::string Base64Decode(const std::string &in) {
    std::string out;
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) {
        T["ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"[i]] = i;
    }

    int val = 0, valb = -8;
    for (unsigned char c : in) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

// Hamming distance function
int HammingDistance(const std::string &s1, const std::string &s2) {
    int distance = 0;
    for (size_t i = 0; i < std::min(s1.size(), s2.size()); ++i) {
        distance += std::bitset<8>(s1[i] ^ s2[i]).count();
    }
    return distance;
}

// Calculate normalized Hamming distance
double NormalizedHammingDistance(const std::string &data, int keySize) {
    double distance = 0.0;
    int numComparisons = 0;

    for (size_t i = 0; i + 2 * keySize <= data.size(); i += keySize) {
        distance += HammingDistance(data.substr(i, keySize), data.substr(i + keySize, keySize));
        numComparisons++;
    }

    return (numComparisons > 0) ? (distance / (numComparisons * keySize)) : std::numeric_limits<double>::max();
}

// Transpose blocks of the ciphertext
std::vector<std::string> TransposeBlocks(const std::string &data, int keySize) {
    std::vector<std::string> blocks(keySize);
    for (size_t i = 0; i < data.size(); ++i) {
        blocks[i % keySize] += data[i];
    }
    return blocks;
}

// Function to score a single-character XOR
double ScoreXOR(const std::string &input) {
    std::map<char, int> frequency = {
        {'E', 12}, {'T', 9}, {'A', 8}, {'O', 7}, {'I', 7},
        {'N', 7}, {'S', 6}, {'H', 6}, {'R', 6}, {'D', 4},
        {'L', 4}, {'C', 3}, {'U', 3}, {'M', 2}, {'W', 2},
        {'F', 2}, {'Y', 2}, {'P', 2}, {'B', 2}, {'V', 1},
        {'K', 1}, {'J', 1}, {'X', 1}, {'Q', 1}, {'Z', 1}
    };

    double score = 0;
    for (char c : input) {
        if (frequency.find(toupper(c)) != frequency.end()) {
            score += frequency[toupper(c)];
        }
    }
    return score;
}

// Decrypt a single-character XOR
char DecryptSingleByteXOR(const std::string &data) {
    char bestChar = 0;
    double bestScore = -1;

    for (int key = 0; key < 256; ++key) {
        std::string decrypted;
        for (char c : data) {
            decrypted += c ^ key;
        }
        double score = ScoreXOR(decrypted);
        if (score > bestScore) {
            bestScore = score;
            bestChar = key;
        }
    }

    return bestChar;
}

// Main function to solve the challenge
int main() {
    // Load and decode the Base64 file
    std::ifstream file("6.txt");
    if (!file) {
        std::cerr << "Error opening the file!" << std::endl;
        return 1;
    }

    std::string base64Data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    std::string cipherText = Base64Decode(base64Data);

    int bestKeySize = 0;
    double bestDistance = std::numeric_limits<double>::max();

    // Determine the best key size
    for (int keySize = 2; keySize <= 40; ++keySize) {
        double normalizedDistance = NormalizedHammingDistance(cipherText, keySize);
        if (normalizedDistance < bestDistance) {
            bestDistance = normalizedDistance;
            bestKeySize = keySize;
        }
    }

    std::cout << "Best key size: " << bestKeySize << "\n";

    // Transpose the blocks
    std::vector<std::string> transposedBlocks = TransposeBlocks(cipherText, bestKeySize);
    std::string key;

    // Decrypt each transposed block
    for (const std::string &block : transposedBlocks) {
        char keyChar = DecryptSingleByteXOR(block);
        key += keyChar;
    }

    std::cout << "Detected key: " << key << "\n";

    // Decrypt the entire ciphertext
    std::string decryptedText;
    for (size_t i = 0; i < cipherText.size(); ++i) {
        decryptedText += cipherText[i] ^ key[i % key.size()];
    }

    std::cout << "Decrypted text: \n" << decryptedText << "\n";

    return 0;
}
