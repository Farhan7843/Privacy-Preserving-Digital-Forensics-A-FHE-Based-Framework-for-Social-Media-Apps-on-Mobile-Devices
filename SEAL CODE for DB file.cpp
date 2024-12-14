#include <iostream>
#include <fstream>
#include <sstream>
#include <vector>
#include <algorithm>
#include <seal/seal.h>
#include <sqlite3.h>  // Include SQLite3 for DB handling

using namespace std;
using namespace seal;

// Function to encrypt and save rows to a binary file
void encrypt_and_save(const vector<string>& rows, const string& output_file, const SEALContext& context, Encryptor& encryptor, BatchEncoder& encoder) {
    ofstream encrypted_file(output_file, ios::binary);
    if (!encrypted_file) {
        cerr << "Error opening output file: " << output_file << endl;
        return;
    }

    for (const auto& row : rows) {
        // Convert row to uint64_t vector
        vector<uint64_t> encoded_data(row.begin(), row.end());
        Plaintext plain;
        encoder.encode(encoded_data, plain);

        Ciphertext encrypted;
        encryptor.encrypt(plain, encrypted);
        encrypted.save(encrypted_file);  // Save encrypted row
    }

    encrypted_file.close();
    cout << "Encryption completed. Data saved to: " << output_file << endl;
}

// Function to load encrypted data and search for a keyword
void load_and_search(const string& input_file, const string& keyword, const SEALContext& context, Decryptor& decryptor, BatchEncoder& encoder) {
    ifstream encrypted_file(input_file, ios::binary);
    if (!encrypted_file) {
        cerr << "Error opening encrypted file: " << input_file << endl;
        return;
    }

    size_t row_number = 0;
    bool found = false;
    vector<size_t> found_rows;

    string lowercase_keyword = keyword;
    transform(lowercase_keyword.begin(), lowercase_keyword.end(), lowercase_keyword.begin(), ::tolower);

    while (encrypted_file.peek() != EOF) {
        Ciphertext encrypted;
        encrypted.load(context, encrypted_file);

        Plaintext decrypted_plaintext;
        decryptor.decrypt(encrypted, decrypted_plaintext);

        // Decode and convert back to string
        vector<uint64_t> decoded_data;
        encoder.decode(decrypted_plaintext, decoded_data);
        string decrypted_row(decoded_data.begin(), decoded_data.end());

        // Convert decrypted row to lowercase
        string lowercase_row = decrypted_row;
        transform(lowercase_row.begin(), lowercase_row.end(), lowercase_row.begin(), ::tolower);

        // Search for the keyword
        if (lowercase_row.find(lowercase_keyword) != string::npos) {
            found = true;
            found_rows.push_back(row_number);
        }
        row_number++;
    }

    encrypted_file.close();

    if (found) {
        cout << "Keyword \"" << keyword << "\" found in these rows: ";
        for (size_t row : found_rows) {
            cout << row << " ";
        }
        cout << endl;
    } else {
        cout << "Keyword \"" << keyword << "\" not found." << endl;
    }
}

// Function to read rows from the SQLite database
vector<string> read_db(const string& db_path, const string& table_name) {
    sqlite3* db;
    sqlite3_stmt* stmt;
    vector<string> rows;

    // Open the database
    int rc = sqlite3_open(db_path.c_str(), &db);
    if (rc) {
        cerr << "Error opening database: " << sqlite3_errmsg(db) << endl;
        return rows;
    }

    // Query to select all rows from the table
    string query = "SELECT * FROM " + table_name;
    rc = sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, 0);
    if (rc != SQLITE_OK) {
        cerr << "Error preparing statement: " << sqlite3_errmsg(db) << endl;
        sqlite3_close(db);
        return rows;
    }

    // Iterate through the rows and add them to the vector
    while (sqlite3_step(stmt) == SQLITE_ROW) {
        string row;
        int col_count = sqlite3_column_count(stmt);
        for (int i = 0; i < col_count; i++) {
            // Handle different data types
            if (sqlite3_column_type(stmt, i) == SQLITE_TEXT) {
                const char* col_text = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                row += string(col_text) + " ";  // Add a space between columns
            }
            else if (sqlite3_column_type(stmt, i) == SQLITE_INTEGER) {
                int col_int = sqlite3_column_int(stmt, i);
                row += to_string(col_int) + " ";
            }
            // Handle other types like BLOB, REAL, etc., if needed
        }
        rows.push_back(row);
    }

    sqlite3_finalize(stmt);
    sqlite3_close(db);

    return rows;
}

int main() {
    // Set up SEAL BFV parameters
    EncryptionParameters parms(scheme_type::bfv);
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::BFVDefault(poly_modulus_degree));
    parms.set_plain_modulus(PlainModulus::Batching(poly_modulus_degree, 20));

    auto context = SEALContext(parms);
    KeyGenerator keygen(context);
    SecretKey secret_key = keygen.secret_key();
    PublicKey public_key;
    keygen.create_public_key(public_key);

    Encryptor encryptor(context, public_key);
    Decryptor decryptor(context, secret_key);
    BatchEncoder encoder(context);

    const string db_file = "/home/zaman/Downloads/mmssms.db";  // Example DB file path
    const string table_name = "sms";  // Example table name
    const string encrypted_output_file = "encrypted_whatsapp_db.bin";
    const string keyword = "id";

    // Step 1: Read the data from the database
    vector<string> rows = read_db(db_file, table_name);
    if (rows.empty()) {
        cerr << "No valid data to encrypt." << endl;
        return 1;
    }

    // Step 2: Encrypt and save the data
    encrypt_and_save(rows, encrypted_output_file, context, encryptor, encoder);

    // Step 3: Load and search the encrypted data for the keyword
    load_and_search(encrypted_output_file, keyword, context, decryptor, encoder);

    return 0;
}

