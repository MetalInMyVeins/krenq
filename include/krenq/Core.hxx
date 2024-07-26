/**
 * Krenq - Universal file encryptor written in C++ 20
 * Copyright (c) 2024 Hossain Md. Fahim <hossainmdfahim66@gmail.com>
 * Licensed under the GNU General Public License v3.0 (GPL-3.0)
 * See the LICENSE file for more information.
 */
#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <exception>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <tuple>
#include <vector>

namespace fs = std::filesystem;

class Krenq
{
public:
  /** Initialize Krenq with list of entries. */
  Krenq(std::initializer_list<std::string>);
  /** Delete assignment constructor. */
  Krenq& operator=(const Krenq&) = delete;
  /** Delete copy constructor. */
  Krenq(const Krenq&) = delete;
  /** Destructor. */
  ~Krenq();
  /** Add entries to Krenq. */
  template <typename... Args>
  void add_entries(Args...);
  /** Remove entries from Krenq. */
  template <typename... Args>
  void remove_entries(Args...);
  /** Save generated key in specified file. */
  void save_key(const std::string&);
  /** Return the number of entries that Krenq currently is managing. */
  size_t get_entry_size() const;

public:
  /** Encrypt all entries that Krenq is currently managing. */
  void encrypt_all();
  /** Encrypt entries by index. */
  template <typename... Args>
  void encrypt_by_index(Args...);
  /** Decrypt all entries that Krenq is currently managing. */
  void decrypt_all(const std::string&);
  /** Decrypt entries by index. */
  template <typename... Args>
  void decrypt_by_index(const std::string&, Args...);
  /** Re-encrypt all entries in runtime with the same key. */
  void re_encrypt_all();
  /** Re-encrypt entries by index. */
  template <typename... Args>
  void re_encrypt_by_index(Args...);

private:
  void generate_key();
  bool encrypt(const std::string&);
  bool decrypt(const std::string&, const std::string&);
  bool re_encrypt(const std::string&);
  void filter_indexes(std::vector<int>&);
  std::string get_string_hash(const std::string&);
  std::string get_random_string(size_t, const std::string& = {});
  long long get_randomN_from_limit(long long, long long);
  std::uint32_t uint32_to_LittleEndian(std::uint32_t);
  std::uint64_t uint64_to_LittleEndian(std::uint64_t);
  std::string get_file_hash(const std::string&);
  typedef std::tuple<bool, std::tuple<short, short, short>, size_t, std::string> type_estatus;
  void krenq_status(const std::string&, Krenq::type_estatus&);
  void add_padding(const std::string&, size_t = 0);
  void remove_padding(const std::string&);
  void make_prefix(std::string&, short = -1, short = -1 , short = -1);
  void extract_key(const std::string&);
  std::string getLocalDatetime();

private:
  /** Vector containing Krenq entries. */
  std::vector<std::string> m_entries{};
  /** Key file name where auto-generated key has been saved. */
  std::string m_keyname{};
  /** If auto-generated key is saved or not. */
  bool m_keyIsSaved{false};
  /** Key struct. */
  struct Key* m_key;
  /** Encrypted key string. */
  std::string m_encryptedKey{};
  // Map containing which entry was decrypted with which key.
  std::map<std::string, std::string> m_emap{};
  // Map containing key and encrypted keystring.
  std::map<std::string, std::string> m_kenmap{};
};

template <typename... Args>
void Krenq::add_entries(Args... args)
{
  std::initializer_list<std::string> entries{args...};
  for (auto entry : entries)
  {
    m_entries.emplace_back((entry));
  }
}

template <typename... Args>
void Krenq::remove_entries(Args... args)
{
  std::initializer_list<std::string> entries{args...};
  for (auto entry : entries)
  {
    auto iter{std::find(m_entries.begin(), m_entries.end(), entry)};
    if (iter != m_entries.end())
    {
      std::iter_swap(iter, m_entries.end() - 1);
      m_entries.pop_back();
    }
  }
}
  
template <typename... Args>
void Krenq::encrypt_by_index(Args... args)
{
  if (!m_keyIsSaved)
  {
    throw std::runtime_error{"Save the key using save_key() before trying to encrypt anything!"};
  }
  std::initializer_list<int> indexes{args...};
  std::vector<int> vidx{indexes};
  this->filter_indexes(vidx);

  // Encrypt by index.
  for (auto i : vidx)
  {
    fs::path entry{m_entries[i - 1]};
    if (!fs::exists(entry)) continue;
    if (fs::is_regular_file(entry))
    {
      this->encrypt(entry.string());
    }
    //
    // If entry is a directory, recurse through it and encrypt all
    // its files.
    //
    else if (fs::is_directory(entry))
      for (auto dfile : fs::recursive_directory_iterator(entry))
        if (fs::is_regular_file(dfile))
        {
          this->encrypt(fs::path{dfile}.string());
        }
  }
}

template <typename... Args>
void Krenq::decrypt_by_index(const std::string& keyname, Args... args)
{
  std::initializer_list<int> indexes{args...};
  std::vector<int> vidx{indexes};
  this->filter_indexes(vidx);

  // Decrypt by index.
  for (auto i : vidx)
  {
    fs::path entry{m_entries[i - 1]};
    if (!fs::exists(entry)) continue;
    if (fs::is_regular_file(entry))
    {
      this->decrypt(entry.string(), keyname);
    }
    //
    // If entry is a directory, recurse through it and encrypt all
    // its files.
    //
    else if (fs::is_directory(entry))
      for (auto dfile : fs::recursive_directory_iterator(entry))
        if (fs::is_regular_file(dfile))
          this->decrypt(fs::path{dfile}.string(), keyname);
  }
}

template <typename... Args>
void Krenq::re_encrypt_by_index(Args... args)
{
  std::initializer_list<int> indexes{args...};
  std::vector<int> vidx{indexes};
  this->filter_indexes(vidx);

  // Re-encrypt by index.
  for (auto i : vidx)
  {
    fs::path entry{m_entries[i - 1]};
    if (!fs::exists(entry)) continue;
    if (!m_emap.contains(entry.string()))
      continue;
    if (fs::is_regular_file(entry))
    {
      this->re_encrypt(entry.string());
    }
    //
    // If entry is a directory, recurse through it and encrypt all
    // its files.
    //
    else if (fs::is_directory(entry))
      for (auto dfile : fs::recursive_directory_iterator(entry))
        if (fs::is_regular_file(dfile))
          this->re_encrypt(fs::path{dfile}.string());
  }
}

/** 
 * Sourced from "sha-2" (https://github.com/amosnier/sha-2)
 * This code is licensed under the Zero Clause BSD license or
 * Unlicense. For more information, see the original project's
 * LICENSE file. Since the rest of this project is under GPLv3,
 * this portion of code is included in accordance with GPLv3
 * licensing terms. By incorporating this code into our project,
 * we're ensuring that the GPLv3 requirements for copyleft and
 * open source are met. 
 * 
 * GPLv3 License: https://www.gnu.org/licenses/gpl-3.0.en.html
 */

#ifdef __cplusplus
extern "C" {
#endif

/*
 * @brief Size of the SHA-256 sum. This times eight is 256 bits.
 */
#define SIZE_OF_SHA_256_HASH 32

/*
 * @brief Size of the chunks used for the calculations.
 *
 * @note This should mostly be ignored by the user, although when using the streaming API, it has an impact for
 * performance. Add chunks whose size is a multiple of this, and you will avoid a lot of superfluous copying in RAM!
 */
#define SIZE_OF_SHA_256_CHUNK 64

/*
 * @brief The opaque SHA-256 type, that should be instantiated when using the streaming API.
 *
 * @note Although the details are exposed here, in order to make instantiation easy, you should refrain from directly
 * accessing the fields, as they may change in the future.
 */
struct Sha_256 {
	uint8_t *hash;
	uint8_t chunk[SIZE_OF_SHA_256_CHUNK];
	uint8_t *chunk_pos;
	size_t space_left;
	uint64_t total_len;
	uint32_t h[8];
};

/*
 * @brief The simple SHA-256 calculation function.
 * @param hash Hash array, where the result is delivered.
 * @param input Pointer to the data the hash shall be calculated on.
 * @param len Length of the input data, in byte.
 *
 * @note If all of the data you are calculating the hash value on is available in a contiguous buffer in memory, this is
 * the function you should use.
 *
 * @note If either of the passed pointers is NULL, the results are unpredictable.
 *
 * @note See note about maximum data length for sha_256_write, as it applies for this function's len argument too.
 */
void calc_sha_256(uint8_t hash[SIZE_OF_SHA_256_HASH], const void *input, size_t len);

/*
 * @brief Initialize a SHA-256 streaming calculation.
 * @param sha_256 A pointer to a SHA-256 structure.
 * @param hash Hash array, where the result will be delivered.
 *
 * @note If all of the data you are calculating the hash value on is not available in a contiguous buffer in memory,
 * this is where you should start. Instantiate a SHA-256 structure, for instance by simply declaring it locally, make
 * your hash buffer available, and invoke this function. Once a SHA-256 hash has been calculated (see further below) a
 * SHA-256 structure can be initialized again for the next calculation.
 *
 * @note If either of the passed pointers is NULL, the results are unpredictable.
 */
void sha_256_init(struct Sha_256 *sha_256, uint8_t hash[SIZE_OF_SHA_256_HASH]);

/*
 * @brief Stream more input data for an on-going SHA-256 calculation.
 * @param sha_256 A pointer to a previously initialized SHA-256 structure.
 * @param data Pointer to the data to be added to the calculation.
 * @param len Length of the data to add, in byte.
 *
 * @note This function may be invoked an arbitrary number of times between initialization and closing, but the maximum
 * data length is limited by the SHA-256 algorithm: the total number of bits (i.e. the total number of bytes times
 * eight) must be representable by a 64-bit unsigned integer. While that is not a practical limitation, the results are
 * unpredictable if that limit is exceeded.
 *
 * @note This function may be invoked on empty data (zero length), although that obviously will not add any data.
 *
 * @note If either of the passed pointers is NULL, the results are unpredictable.
 */
void sha_256_write(struct Sha_256 *sha_256, const void *data, size_t len);

/*
 * @brief Conclude a SHA-256 streaming calculation, making the hash value available.
 * @param sha_256 A pointer to a previously initialized SHA-256 structure.
 * @return Pointer to the hash array, where the result is delivered.
 *
 * @note After this function has been invoked, the result is available in the hash buffer that initially was provided. A
 * pointer to the hash value is returned for convenience, but you should feel free to ignore it: it is simply a pointer
 * to the first byte of your initially provided hash array.
 *
 * @note If the passed pointer is NULL, the results are unpredictable.
 *
 * @note Invoking this function for a calculation with no data (the writing function has never been invoked, or it only
 * has been invoked with empty data) is legal. It will calculate the SHA-256 value of the empty string.
 */
uint8_t *sha_256_close(struct Sha_256 *sha_256);

#ifdef __cplusplus
}
#endif




