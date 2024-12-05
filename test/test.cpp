#include <gtest/gtest.h>
#include <string>
#include <utility>
#include "../src/main.cpp" // Replace with the actual file containing the functions

// Test for hamming_distance
TEST(CryptoTests, HammingDistanceTest) {
    EXPECT_EQ(hamming_distance("this is a test", "wokka wokka!!!"), 37);
    EXPECT_THROW(hamming_distance("short", "longerstring"), std::runtime_error);
}

// Test for get_english_score
TEST(CryptoTests, EnglishScoreTest) {
    EXPECT_NEAR(get_english_score("hello world"), 0.509, 0.001);
    EXPECT_NEAR(get_english_score("fjdsfjsdlf"), 0.0, 0.001); // Gibberish, low score
}

// Test for singlechar_xor_brute_force
TEST(CryptoTests, SingleCharXORBruteForceTest) {
    std::string input = "your test data here"; // Replace with meaningful test data
    auto result = singlechar_xor_brute_force(input);
    EXPECT_GE(result.second, 0.0);
    EXPECT_LE(result.first, 255);
}

// Test for repeating_key_xor
TEST(CryptoTests, RepeatingKeyXORTest) {
    std::string plaintext = "hello world";
    std::string key = "key";
    std::string expected_ciphertext = repeating_key_xor(plaintext, key);
    EXPECT_EQ(repeating_key_xor(expected_ciphertext, key), plaintext);
}

// Test for base64_decode
TEST(CryptoTests, Base64DecodeTest) {
    std::string b64input = "SGVsbG8gd29ybGQ="; // "Hello world" in Base64
    EXPECT_EQ(base64_decode(b64input), "Hello world");
    EXPECT_THROW(base64_decode("invalid base64!"), std::runtime_error);
}

// Test for break_repeating_key_xor
TEST(CryptoTests, BreakRepeatingKeyXORTest) {
    std::string binary_data = repeating_key_xor("Hello world", "key");
    auto result = break_repeating_key_xor(binary_data);
    EXPECT_EQ(result.second, "key");
    EXPECT_EQ(result.first, "Hello world");
}

// Test for read_file
TEST(CryptoTests, ReadFileTest) {
    // Create a temporary file with known content
    std::ofstream temp_file("temp.txt");
    temp_file << "Hello world";
    temp_file.close();

    // Test read_file function
    EXPECT_EQ(read_file("temp.txt"), "Hello world");

    // Clean up
    std::remove("temp.txt");

    // Test file-not-found exception
    EXPECT_THROW(read_file("non_existent_file.txt"), std::runtime_error);
}
