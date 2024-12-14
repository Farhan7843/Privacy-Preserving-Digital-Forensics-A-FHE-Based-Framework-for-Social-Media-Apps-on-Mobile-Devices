#include "seal/seal.h"
#include <iostream>
#include <vector>
#include <fstream>
#include <string>
#include <sstream>
#include <nlohmann/json.hpp>  // Include nlohmann/json library

using json = nlohmann::json;
using namespace std;
using namespace seal;

// Function to encrypt each character of the JSON string
void encrypt_data(const string& json_str, Encryptor& encryptor, vector<Ciphertext>& encrypted_data) {
    for (char c : json_str) {
        Plaintext pt(to_string(int(c))); // Convert char to ASCII
        Ciphertext ct;
        encryptor.encrypt(pt, ct); // Encrypt the character
        encrypted_data.push_back(ct);
    }
}

// Function to search for a keyword in the encrypted data
void search_keyword(const string& keyword, const vector<Ciphertext>& encrypted_data,
                    Encryptor& encryptor, Decryptor& decryptor) {
    // Print the keyword being searched
    cout << "Keyword \"" << keyword << "\" ";

    vector<int> keyword_ascii;
    for (char c : keyword) {
        keyword_ascii.push_back(int(c)); // Convert keyword to ASCII
    }

    // Encrypt the keyword as well
    vector<Ciphertext> encrypted_keyword;
    for (int ascii : keyword_ascii) {
        Plaintext pt(to_string(ascii)); // Convert to ASCII string
        Ciphertext ct;
        encryptor.encrypt(pt, ct); // Encrypt the keyword character
        encrypted_keyword.push_back(ct);
    }

    // Search for exact matches
    bool found_match = false;
    for (size_t i = 0; i < encrypted_data.size(); ++i) {
        bool match = true;
        for (size_t j = 0; j < encrypted_keyword.size(); ++j) {
            Ciphertext encrypted_char = encrypted_data[i + j];
            Plaintext decrypted_char;
            decryptor.decrypt(encrypted_char, decrypted_char);  // Decrypt the ciphertext
            if (stoi(decrypted_char.to_string()) != keyword_ascii[j]) {
                match = false;
                break;
            }
        }

        if (match) {
            found_match = true;
            cout << "Match found at position: " << i << endl;
        }
    }

    if (!found_match) {
        cout << "No matches found." << endl;
    }
}

int main() {
    // Load the JSON data from a file using nlohmann::json
    ifstream file("/home/zaman/Downloads/season1.json");
    json json_data;
    file >> json_data;  // Parse the JSON data into json_data
    string json_str = json_data.dump();  // Convert the JSON object into a string

    // Set up SEAL parameters for BFV scheme
    EncryptionParameters parms(scheme_type::bfv);
    parms.set_poly_modulus_degree(8192);  // Set to a power of 2
    parms.set_coeff_modulus(CoeffModulus::Create(8192, {60, 40, 60}));  // Set coefficients
    parms.set_plain_modulus(4096);  // Reasonable value for plain modulus

    SEALContext context(parms);
    KeyGenerator keygen(context);

    // Generate public and secret keys
    PublicKey public_key;
    keygen.create_public_key(public_key);  // Extract PublicKey
    SecretKey secret_key = keygen.secret_key();  // Generate SecretKey
    Encryptor encryptor(context, public_key);  // Initialize Encryptor
    Decryptor decryptor(context, secret_key);  // Initialize Decryptor

    vector<Ciphertext> encrypted_data;

    // Encrypt the entire JSON data
    encrypt_data(json_str, encryptor, encrypted_data);

    // Output the encrypted data size (optional for debugging)
    cout << "Encrypted data size: " << encrypted_data.size() << endl;

    // Define the keyword to search for (can be changed)
    string keyword = "stark";  // You can change this to any other keyword

    // Search for the keyword in encrypted data
    search_keyword(keyword, encrypted_data, encryptor, decryptor);

    return 0;
}

