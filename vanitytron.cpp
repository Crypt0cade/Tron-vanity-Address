#include <iostream>
#include <random>
#include <vector>
#include <openssl/evp.h>
#include <string>
#include <libbase58.h>
#include <secp256k1.h>
#include <iomanip>
#include "Keccak256.hpp"
#include <fstream>

void print_hex(const unsigned char* data, size_t len) {
  for (size_t i = 0; i < len; ++i) {
    printf("%02x", data[i]);
  }
  printf("\n");
}

bool my_sha256(void *digest, const void *data, size_t datasz)
 {
  if (!digest || !data) {
    return false;
  }

  EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
  if (!mdctx) {
    return false;
  }

  if (EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr) != 1) {
    EVP_MD_CTX_free(mdctx);
    return false;
  }

  if (EVP_DigestUpdate(mdctx, data, datasz) != 1) {
    EVP_MD_CTX_free(mdctx);
    return false;
  }

  if (EVP_DigestFinal_ex(mdctx, static_cast<unsigned char *>(digest), nullptr) != 1) {
    EVP_MD_CTX_free(mdctx);
    return false;
  }

  EVP_MD_CTX_free(mdctx);
  return true;
}

int main(int argc, char* argv[]) {
  // Handle command-line arguments
  if (argc < 2 || argc > 4) {
    std::cerr << "Usage: " << argv[0] << " [-s string] [-e string] [-c]" << std::endl;
    std::cerr << "-s: Search for strings at the beginning (excluding prefix)" << std::endl;
    std::cerr << "-e: Search for strings at the end of the address" << std::endl;
    std::cerr << "-c: Case-sensitive search" << std::endl;
    return 1;
  }

  std::string search_string;
  bool search_start = false, search_end = false, case_sensitive = false;
  for (int i = 1; i < argc; ++i) {
    std::string arg(argv[i]);
    if (arg == "-s") {
      if (i + 1 >= argc) {
        std::cerr << "Error: -s requires a search string" << std::endl;
        return 1;
      }
      search_string = argv[i + 1];
      search_start = true;
      ++i; // Skip the next argument (search string)
    } else if (arg == "-e") {
      if (i + 1 >= argc) {
        std::cerr << "Error: -e requires a search string" << std::endl;
        return 1;
      }
      search_string = argv[i + 1];
      search_end = true;
      ++i; // Skip the next argument (search string)
    } else if (arg == "-c") {
      case_sensitive = true;
    } else {
      std::cerr << "Error: Unknown argument: " << arg << std::endl;
      return 1;
    }
  }

  std::cout << "Searching for vanity Tron address..." << std::endl;

  // Create context for secp256k1 operations
  secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
  if (!ctx) {
    std::cerr << "Error creating secp256k1 context" << std::endl;
    return 1;
  }

  std::random_device rd;
  std::mt19937 gen(rd());
  std::uniform_int_distribution<unsigned char> dist(0, 255);

  unsigned char priv_key[32];
  for (size_t i = 0; i < 32; ++i) {
    priv_key[i] = dist(gen);
  }

  while (true) {
    // Generate a random private key
    for (size_t i = 0; i < 32; ++i) {
      priv_key[i] = dist(gen);
    }

    secp256k1_pubkey pubkey;
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, priv_key)) {
      std::cerr << "Error generating public key" << std::endl;
      secp256k1_context_destroy(ctx);
      return 1;
    }

    size_t len = 65;
    unsigned char pubkey_bytes[len];
    if (!secp256k1_ec_pubkey_serialize(ctx, pubkey_bytes, &len, &pubkey, SECP256K1_EC_UNCOMPRESSED)) {
      std::cerr << "Error serializing public key" << std::endl;
      secp256k1_context_destroy(ctx);
      return 1;
    }

    std::vector<unsigned char> public_key_without_prefix(pubkey_bytes + 1, pubkey_bytes + len);

    uint8_t hash[Keccak256::HASH_LEN];
    Keccak256::getHash(public_key_without_prefix.data(), public_key_without_prefix.size(), hash);

    std::vector<unsigned char> address_hash(hash + 12, hash + 32);

    if (address_hash.size() != 20) {
      std::cerr << "Error" << std::endl;
      secp256k1_context_destroy(ctx);
      return 1;
    }

    b58_sha256_impl = my_sha256;

    std::vector<unsigned char> data = address_hash;

    // Codificar en Base58check
    size_t base58_size = 0;
    b58check_enc(nullptr, &base58_size, 0x41, data.data(), data.size());
    
    // Allocate memory for base58_address, checking for success
    char *base58_address = (char*)malloc(base58_size);
    if (base58_address == nullptr) {
        std::cerr << "Error allocating memory for base58 address" << std::endl;
        secp256k1_context_destroy(ctx);
        return 1;
    }

    b58check_enc(base58_address, &base58_size, 0x41, data.data(), data.size());

    std::string address = base58_address;

      // Check if the address matches the search criteria
    bool found = true;
    if (search_start) {
      if (case_sensitive) {
         found &= address.substr(1, search_string.length()) == search_string;
       } else {
         found &= std::equal(search_string.begin(), search_string.end(), address.begin() + 1, [](char a, char b) {
           return std::tolower(a) == std::tolower(b);
         });
       }
     }
     if (search_end) {
       if (case_sensitive) {
         found &= address.substr(address.length() - search_string.length()) == search_string;
       } else {
         found &= std::equal(search_string.rbegin(), search_string.rend(), address.rbegin(), [](char a, char b) {
           return std::tolower(a) == std::tolower(b);
         });
       }
     }

     if (found) {
       std::cout << "Found vanity address: " << address << std::endl;
       std::cout << "Private key: ";
       print_hex(priv_key, 32);

       // Guardar en archivo
       std::ofstream output_file("vanity_addresses.txt", std::ios::app); // Abre el archivo en modo append
       if (output_file.is_open()) {
         output_file << "Address: " << address << std::endl;
         output_file << "Private key: ";
         for (unsigned char byte : priv_key) {
           output_file << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(byte);
         }
         output_file << std::endl << std::endl;
         output_file.close();
         std::cout << "Results saved to vanity_addresses.txt" << std::endl;
       } else {
         std::cerr << "Error opening file for writing" << std::endl;
       }
       std::cout << "Eureka!" << std::endl; // Imprimir el mensaje de éxito
       return 0;
        }
    }
  }


