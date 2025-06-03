#include <iostream>    // For input/output (like std::cout)
#include <string>      // For std::string
#include <vector>      // For std::vector (we'll use this for dynamic buffers!)
#include <windows.h>  // Essential for most Windows API functions
#include <wincrypt.h> // Specific header for CryptoAPI definitions (constants like MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CALG_SHA_256, CALG_AES_256)
#include <iomanip>     // For std::hex, std::setw, std::setfill for hexadecimal output
#include <sstream>     // For std::stringstream to format hex output
#include <fstream>     // For file input/output operations
#include <algorithm>   // For std::min (needed for limited hex output display)
#include <ios>         // REQUIRED: For std::ios::binary and std::ios::ate types to resolve ifstream constructor


// function to convert a byte vector to a hexadecimal string for display
std::string BytesToHex(const std::vector<BYTE>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (BYTE b : bytes) { // Range-based for loop, requires C++11 or later
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}
//_______________________________________________________

// Function to read entire file into a vector<BYTE>
std::vector<BYTE> ReadFileToBytes(const std::string& filepath) {
    std::ifstream infile(filepath.c_str(), std::ios::binary | std::ios::ate);
    if (!infile.is_open()) {
        std::cerr << "ERROR: Could not open file for reading: " << filepath << std::endl;
        return {}; // Return empty vector on error
    }
    std::streamsize size = infile.tellg();// Get file size
    if (size < 0) {
        std::cerr << "ERROR: Failed to get file size for: " << filepath << std::endl;
        infile.close();
        return {};
    }

    // Resize buffer to file size, reset read pointer, and read entire file content into the buffer.
    std::vector<BYTE> buffer(static_cast<DWORD>(size));
    infile.seekg(0, std::ios::beg);
    if (!infile.read(reinterpret_cast<char*>(buffer.data()), static_cast<DWORD>(size))) {
        std::cerr << "ERROR: Failed to read from file: " << filepath << std::endl;
        infile.close();
        return {};
    }
    infile.close();
    return buffer;// Returns a std::vector<BYTE> containing the entire content of the file.
}

// Function to write vector<BYTE> to a file
bool WriteBytesToFile(const std::string& filepath, const std::vector<BYTE>& data) {
    std::ofstream outfile(filepath.c_str(), std::ios::binary);
    if (!outfile.is_open()) {
        std::cerr << "ERROR: Could not open file for writing: " << filepath << std::endl;
        return false;
    }
   outfile.write(reinterpret_cast<const char*>(data.data()), data.size());
    outfile.close();
    return true;
}



//@brief Encrypts a vector of bytes using AES-256 derived from a passphrase.
//
//@param plaintext The data to be encrypted.
//@param passphrase The passphrase used to derive the encryption key.
//@return A vector containing the encrypted ciphertext, or an empty vector on error.
std::vector<BYTE> EncryptData(const std::vector<BYTE>& plaintext, const std::string& passphrase) {
    // These handles are now LOCAL to this function.
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    std::vector<BYTE> ciphertext_buffer; // This will hold our encrypted data

    // 1. Acquire Cryptographic Context
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error in EncryptData: CryptAcquireContext failed. Error Code: " << GetLastError() << std::endl; // For production, log this. For functions, just return.
        return {}; // Return empty vector on error
    }

    // 2. Create Hash Object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
          std::cerr << "Error in EncryptData: CryptCreateHash failed. Error Code: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return {};
    }

    // 3. Hash the Passphrase
    if (!CryptHashData(hHash, (BYTE*)passphrase.data(), passphrase.length(), 0)) {
          std::cerr << "Error in EncryptData: CryptHashData failed. Error Code: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    // 4. Derive Key from Hash
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
        std::cerr << "Error in EncryptData: CryptDeriveKey failed. Error Code: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    // 5. Determine required buffer size for encryption (including padding)
    DWORD data_len = static_cast<DWORD>(plaintext.size());
    DWORD buffer_size = data_len;
    // Call CryptEncrypt once with NULL data buffer to get required buffer size
    if (!CryptEncrypt(hKey, 0, TRUE, 0, NULL, &buffer_size, data_len)) {
        std::cerr << "Error in EncryptData: Getting encryption buffer size failed. Error Code: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey); CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
        return {};
    }
    ciphertext_buffer.resize(buffer_size); // Resize buffer to hold encrypted data

    // Copy plaintext to the buffer for in-place encryption
    // pass  plaintext to the function, then copy it into our mutable buffer.
    std::copy(plaintext.begin(), plaintext.end(), ciphertext_buffer.begin());


    // 6. Perform Encryption
    // data_len will be updated to the actual encrypted data length after this call
    if (!CryptEncrypt(hKey, 0, TRUE, 0, ciphertext_buffer.data(), &data_len, buffer_size)) {
        std::cerr << "Error in EncryptData: CryptEncrypt failed. Error Code: " << GetLastError() << std::endl;
        CryptDestroyKey(hKey); CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
        return {};
    }

    // Resize the buffer to the actual encrypted data length
    ciphertext_buffer.resize(data_len);

    // 7. Cleanup (Important! Always release resources)
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return ciphertext_buffer; // Return the encrypted data
}
//_______________________________________________________


//@brief Decrypts a vector of bytes using AES-256 derived from a passphrase.
//
//@param ciphertext The data to be decrypted.
//@param passphrase The passphrase used to derive the decryption key.
//@return A vector containing the decrypted plaintext, or an empty vector on error.
//
std::vector<BYTE> DecryptData(const std::vector<BYTE>& ciphertext, const std::string& passphrase) {
    // These handles are now LOCAL to this function.
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hKey = 0;
    //mutable copy of the ciphertext, as CryptDecrypt modifies in-place.
    std::vector<BYTE> plaintext_buffer = ciphertext;

    // 1. Acquire Cryptographic Context
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        std::cerr << "Error in DecryptData: CryptAcquireContext failed. Error Code: " << GetLastError() << std::endl;
        return {};
    }

    // 2. Create Hash Object
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
          std::cerr << "Error in DecryptData: CryptCreateHash failed. Error Code: " << GetLastError() << std::endl;
        CryptReleaseContext(hProv, 0);
        return {};
    }

    // 3. Hash the Passphrase
    if (!CryptHashData(hHash, (BYTE*)passphrase.data(), passphrase.length(), 0)) {
        std::cerr << "Error in DecryptData: CryptHashData failed. Error Code: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    // 4. Derive Key from Hash
    if (!CryptDeriveKey(hProv, CALG_AES_256, hHash, 0, &hKey)) {
          std::cerr << "Error in DecryptData: CryptDeriveKey failed. Error Code: " << GetLastError() << std::endl;
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return {};
    }

    // 5. Perform Decryption
    DWORD data_len = static_cast<DWORD>(plaintext_buffer.size());
    if (!CryptDecrypt(hKey, 0, TRUE, 0, plaintext_buffer.data(), &data_len)) {
        std::cerr << "Error in DecryptData: CryptDecrypt failed. Error Code: " << GetLastError() << std::endl;
        // Specifically for incorrect keys, GetLastError() might be NTE_BAD_KEY.
        CryptDestroyKey(hKey); CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0);
        return {};
    }

    // Resize the buffer to the actual decrypted data length (removes padding)
    plaintext_buffer.resize(data_len);

    // 6. Cleanup
    CryptDestroyKey(hKey);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);

    return plaintext_buffer; // Return the decrypted data
}
//_________________________________________

    // --- Main function for testing/demonstration ---
int main() {
    std::string passphrase = "MySuperSecretLogKey"; // default passphrase for this demo

    std::cout << "--- Starting Application Security Demo ---" << std::endl;
    std::cout << "------------------------------------------" << std::endl;

   

    // --- Demo : Encrypting and Decrypting a File ---
    std::string input_filename = "input.txt";
    std::string encrypted_file_name = "encrypted.bin";
    std::string decrypted_file_name = "decrypted_output.txt";

    std::cout << "\n[Demo ] File Encryption/Decryption (" << input_filename << ")" << std::endl;

    /* Create a dummy input.txt if it doesn't exist for the demo
    //  try to read it first; if empty, assume it doesn't exist or is empty and create content
    if (ReadFileToBytes(input_filename).empty()) {
        std::cout << "  * Creating a dummy " << input_filename << " file." << std::endl;
        std::string dummy_content = "This is a test log entry for the hackathon. It contains sensitive information.\nLine 2: User: JohnDoe, IP: 192.168.1.50\nLine 3: Alert: Malicious activity detected.";
        if (!WriteBytesToFile(input_filename, std::vector<BYTE>(dummy_content.begin(), dummy_content.end()))) {
            std::cerr << "  Failed to create dummy " << input_filename << ". Skipping file demo." << std::endl;
        }
    }*/


    std::vector<BYTE> file_plaintext = ReadFileToBytes(input_filename); 
    if (!file_plaintext.empty()) {
        std::cout << "  * Read " << file_plaintext.size() << " bytes from " << input_filename << std::endl;

        std::cout << "  * Encrypting file data..." << std::endl;
        std::vector<BYTE> encrypted_file_data = EncryptData(file_plaintext, passphrase);

        if (!encrypted_file_data.empty()) {
            WriteBytesToFile(encrypted_file_name, encrypted_file_data);
            std::cout << "  * Encrypted content written to: " << encrypted_file_name << std::endl;
            
           std::cout <<"\n Encrypted data in hex : "<<BytesToHex(encrypted_file_data);
        } else {
            std::cerr << " \n File encryption failed!" << std::endl;
        }
    } else {
        std::cerr << "  Skipping file encryption demo due to input file error." << std::endl;
    }


    std::cout << "  * Decrypting file data..." << std::endl;
    std::vector<BYTE> file_ciphertext = ReadFileToBytes(encrypted_file_name); 
    if (!file_ciphertext.empty()) {
        std::vector<BYTE> decrypted_file_data = DecryptData(file_ciphertext, passphrase); 

        if (!decrypted_file_data.empty()) {
            WriteBytesToFile(decrypted_file_name, decrypted_file_data); // <--- USING YOUR HELPER!
            std::cout << "  * Decrypted content written to: " << decrypted_file_name << std::endl;
            std::string final_decrypted_str(decrypted_file_data.begin(), decrypted_file_data.end());
            
            std::cout << "  Content (first 100 chars): \"" << final_decrypted_str.substr(0, std::min(100, (int)final_decrypted_str.length())) << "...\"" << std::endl;
        } else {
            std::cerr << "  File decryption failed!" << std::endl;
        }
    } else {
        std::cerr << "  Skipping file decryption demo due to encrypted file error." << std::endl;
    }

    std::cout << "\n------------------------------------------" << std::endl;
    std::cout << " demo completed. Press Enter to exit." << std::endl;
    std::cin.ignore();
    return 0;
}



