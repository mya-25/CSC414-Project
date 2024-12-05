#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <algorithm>
#include <stdexcept>
#include <cmath>
#include <numeric>
#include <iterator>
#include <tuple>
#include <bitset>
#include <fstream>
#include <sstream>
#include <iomanip>

#include <cstdint>

using namespace std;

// Character frequency based on English language statistics
const unordered_map<char, double> CHARACTER_FREQ = {
    {'a', 0.0651738}, {'b', 0.0124248}, {'c', 0.0217339}, {'d', 0.0349835},
    {'e', 0.1041442}, {'f', 0.0197881}, {'g', 0.0158610}, {'h', 0.0492888},
    {'i', 0.0558094}, {'j', 0.0009033}, {'k', 0.0050529}, {'l', 0.0331490},
    {'m', 0.0202124}, {'n', 0.0564513}, {'o', 0.0596302}, {'p', 0.0137645},
    {'q', 0.0008606}, {'r', 0.0497563}, {'s', 0.0515760}, {'t', 0.0729357},
    {'u', 0.0225134}, {'v', 0.0082903}, {'w', 0.0171272}, {'x', 0.0013692},
    {'y', 0.0145984}, {'z', 0.0007836}, {' ', 0.1918182}
};


int popcount(uint32_t x) {
    int count = 0;
    while (x) {
        count += x & 1;
        x >>= 1;
    }
    return count;
}

// Function to calculate Hamming Distance
int hamming_distance(const string& binary_seq_1, const string& binary_seq_2) {
    if (binary_seq_1.length() != binary_seq_2.length()) {
        throw runtime_error("Inputs must be of equal length");
    }
    int dist = 0;
    for (size_t i = 0; i < binary_seq_1.length(); i++) {
        int diff = binary_seq_1[i] ^ binary_seq_2[i];
        dist += popcount(diff); // Count the number of 1 bits
    }
    return dist;
}

// Function to calculate English score based on character frequency
double get_english_score(const string& input) {
    double score = 0.0;
    for (char c : input) {
        auto it = CHARACTER_FREQ.find(tolower(c));
        if (it != CHARACTER_FREQ.end()) {
            score += it->second;
        }
    }
    return score;
}



// Function to perform Single Character XOR with brute force
pair<int, double> singlechar_xor_brute_force(const string& input) {
    vector<pair<int, double>> candidates; // (key, score)
    for (int key_candidate = 0; key_candidate < 256; ++key_candidate) {
        string plaintext_candidate;
        for (char c : input) {
            plaintext_candidate += c ^ key_candidate;
        }
        double score = get_english_score(plaintext_candidate);
        candidates.push_back({ key_candidate, score });
    }
    // Sort candidates by score in descending order and return the top candidate
    auto best_candidate = *max_element(candidates.begin(), candidates.end(),
        [](const pair<int, double>& a, const pair<int, double>& b) {
            return a.second < b.second;
        });
    return best_candidate; // Return the best key and its score
}

// Function to perform Repeating Key XOR encryption/decryption
string repeating_key_xor(const string& plaintext, const string& key) {
    string ciphertext;
    size_t key_index = 0;
    for (char c : plaintext) {
        ciphertext += c ^ key[key_index];
        key_index = (key_index + 1) % key.size();
    }
    return ciphertext;
}

// Function to decode base64 string to binary string
string base64_decode(const string& b64input) {
    static const string b64chars =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz"
        "0123456789+/";
    string output;
    int bits_collected = 0;
    int accumulator = 0;
    for (char c : b64input) {
        if (isspace(c) || c == '=') continue;
        auto pos = b64chars.find(c);
        if (pos == string::npos) throw runtime_error("Invalid base64 input");

        accumulator = (accumulator << 6) + pos;
        bits_collected += 6;

        if (bits_collected >= 8) {
            bits_collected -= 8;
            output += (accumulator >> bits_collected) & 0xFF;
        }
    }
    return output;
}

// Function to break repeating key XOR encryption
pair<string, string> break_repeating_key_xor(const string& binary_data) {
    unordered_map<int, double> normalized_distances;
    for (int key_size = 2; key_size <= 40; ++key_size) {
        vector<string> chunks;
        for (size_t i = 0; i < binary_data.size(); i += key_size) {
            chunks.push_back(binary_data.substr(i, key_size));
        }

        double distance = 0.0;
        size_t num_pairs = 0;
        for (size_t i = 0; i < chunks.size(); ++i) {
            for (size_t j = i + 1; j < chunks.size(); ++j) {
                if (chunks[i].length() != chunks[j].length()) {
                    continue; // Skip if lengths differ
                }
                distance += hamming_distance(chunks[i], chunks[j]);
                num_pairs++;
            }
        }

        // Average the distance
        if (num_pairs > 0) {
            distance /= num_pairs;
            normalized_distances[key_size] = distance / key_size; // Normalize distance
        }
    }

    // Get the three smallest normalized distances
    vector<int> possible_key_sizes;
    for (const auto& entry : normalized_distances) {
        possible_key_sizes.push_back(entry.first);
    }
    sort(possible_key_sizes.begin(), possible_key_sizes.end(),
        [&normalized_distances](int a, int b) {
            return normalized_distances[a] < normalized_distances[b];
        });

    possible_key_sizes.resize(min(static_cast<size_t>(3), possible_key_sizes.size())); // Keep top 3 key sizes
    vector<pair<string, string>> possible_plaintexts; // (plaintext, key)

    for (int d : possible_key_sizes) {
        string key;
        for (int i = 0; i < d; ++i) {
            string block;
            for (size_t j = i; j < binary_data.size(); j += d) {
                if (j < binary_data.size()) {
                    block += binary_data[j];
                }
            }
            // Get the best key for this block
            int best_key = singlechar_xor_brute_force(block).first;
            key += static_cast<char>(best_key);
        }
        // Decrypt the original data with this key
        string decrypted_text = repeating_key_xor(binary_data, key);
        possible_plaintexts.push_back({ decrypted_text, key });
    }

    // Return the plaintext with the best score
    return *max_element(possible_plaintexts.begin(), possible_plaintexts.end(),
        [](const pair<string, string>& a, const pair<string, string>& b) {
            return get_english_score(a.first) < get_english_score(b.first);
        });
}

// Function to read the contents of a file
string read_file(const string& filename) {
    ifstream file(filename);
    if (!file) {
        throw runtime_error("Unable to open file");
    }
    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

int main() {
    try {
        // Read the base64 encoded data from file
        string b64_data = read_file("E:\\downloads\\6.txt");


        // Decode base64 to binary data
        string binary_data = base64_decode(b64_data);

        // Break the repeating key XOR encryption
        auto result = break_repeating_key_xor(binary_data);

        // Output the key and the decrypted text
        cout << "Key = " << result.second << endl;
        cout << "Decrypted Text = " << result.first << endl;

    }
    catch (const exception& e) {
        cerr << "Error: " << e.what() << endl;
    }
    return 0;
}