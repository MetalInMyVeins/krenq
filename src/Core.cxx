/**
 * Krenq - Universal file encryptor written in C++ 20
 * Copyright (c) 2024 Hossain Md. Fahim <hossainmdfahim66@gmail.com>
 * Licensed under the GNU General Public License v3.0 (GPL-3.0)
 * See the LICENSE file for more information.
 */
#include "krenq/Core.hxx"
#include <cmath>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <sstream>

// Holds length of string in Key.
static const int g_kslen{16};
typedef std::uint32_t type1;
typedef std::uint64_t type2;
typedef char type3;
// 
// The Key struct.
//
#ifdef _MSC_VER
  #pragma pack(push, 1)
  struct Key
  {
    type1 s_kid{};
    type3 s_ksport1[g_kslen]{};
    type2 s_rt1{};
    type3 s_ksport2[g_kslen]{};
    type2 s_rt2{};
    type3 s_ksport3[g_kslen]{};
    type2 s_rt3{};
    type3 s_ksport4[g_kslen]{};
    type2 s_rt4{};
  };
  #pragma pack(pop)
#elif defined(__GNUC__) || defined(__clang__)
  struct __attribute__((packed)) Key
  {
    type1 s_kid{};
    type3 s_ksport1[g_kslen]{};
    type2 s_rt1{};
    type3 s_ksport2[g_kslen]{};
    type2 s_rt2{};
    type3 s_ksport3[g_kslen]{};
    type2 s_rt3{};
    type3 s_ksport4[g_kslen]{};
    type2 s_rt4{};
  };
#endif

// Holds the length of actual key.
static const size_t g_actualKlen{154};
// Holds length of encrypted key.
static const size_t g_encryptedKlen{sizeof(Key)};
// Holds the actual key.
static std::string g_actualKey{};
// Map containing extracted key values.
static std::map<std::string, std::string> g_kmap{};

// Constructor.
Krenq::Krenq(std::initializer_list<std::string> entries)
  : m_entries{entries},
    m_key{new Key}
{
  // New and unique key will be generated only when Krenq is
  // constructed.
  this->generate_key();
}

// Destructor.
Krenq::~Krenq()
{
  delete m_key;
}

// Return number of entries in Krenq.
size_t Krenq::get_entry_size() const
{
  return m_entries.size();
}

// Generates a unique key.
void Krenq::generate_key()
{
  // Generate values to populate m_key.
  std::srand(std::time(nullptr));
  m_key->s_kid = this->uint32_to_LittleEndian(static_cast<type1>((std::rand())));
  std::strncpy(m_key->s_ksport1, this->get_random_string(g_kslen - 1).c_str(), g_kslen - 1);
  m_key->s_rt1 = this->uint64_to_LittleEndian(static_cast<type2>(std::rand()));
  std::strncpy(m_key->s_ksport2, this->get_random_string(g_kslen - 1).c_str(), g_kslen - 1);
  m_key->s_rt2 = this->uint64_to_LittleEndian(static_cast<type2>(std::rand()));
  std::strncpy(m_key->s_ksport3, this->get_random_string(g_kslen - 1).c_str(), g_kslen - 1);
  m_key->s_rt3 = this->uint64_to_LittleEndian(static_cast<type2>(std::rand()));
  std::strncpy(m_key->s_ksport4, this->get_random_string(g_kslen - 1).c_str(), g_kslen - 1);
  m_key->s_rt4 = this->uint64_to_LittleEndian(static_cast<type2>(std::rand()));

  // Make the actual key.
  g_actualKey += std::to_string(m_key->s_kid);
  g_actualKey += m_key->s_ksport1;
  g_actualKey += std::to_string(m_key->s_rt1);
  g_actualKey += m_key->s_ksport2;
  g_actualKey += std::to_string(m_key->s_rt2);
  g_actualKey += m_key->s_ksport3;
  g_actualKey += std::to_string(m_key->s_rt3);
  g_actualKey += m_key->s_ksport4;
  g_actualKey += std::to_string(m_key->s_rt4);
  
  // Due to assoication of random numbers in g_actualKstr, the
  // random numbers wouldn't always be of their maximum size and
  // as a result the string wouldn't be of it's maximum length
  // (which is 154) too. So g_actualKstr should be padded. Add
  // padding at the end of g_actualKstr to make it 154 bytes long.
  size_t diff{g_actualKlen - g_actualKey.length()};
  g_actualKey += g_actualKey.substr(0, diff);

  // Write raw binary format of Key to m_encryptedKstr. It has to
  // be ensured first that Key is packed and the internal data is
  // in little endian format.
  std::stringstream obuffer;
  obuffer.write(reinterpret_cast<char*>(m_key), sizeof(Key));
  m_encryptedKey = obuffer.str();
}

//
// This would only expect a single vaild file, nothing else. No
// error checking would be done here. The sole purpose is to
// encrypt. So do any pre-encryption steps beforehand.
// return true would mean entry has been successfully encrypted.
//
bool Krenq::encrypt(const std::string& filename)
{
  Krenq::type_estatus estatus{};
  this->krenq_status(filename, estatus);
  // If file is already encrypted, no need to encrypt.
  if (std::get<0>(estatus)) return false;
  // No need to encrypt empty files.
  size_t filesize{std::get<2>(estatus)};
  if (filesize == 0) return false;
  // Past this point, we gotta encrypt the file.
  // Get the original file hash first.
  std::string filehash{this->get_file_hash(filename)};
  // Create a random prefix.
  std::string prefix{};
  this->make_prefix(prefix);
  // Get encrypted key hash.
  std::string kenhash{this->get_string_hash(m_encryptedKey)};
  // Add padding to the file.
  this->add_padding(filename, filesize);
  // Create temporary file to write data.
  std::fstream ofile{filename + ".krenqenctemp", std::ios::out | std::ios::binary};
  ofile << filehash << prefix;
  // Open original file for reading.
  std::fstream ifile{filename, std::ios::in | std::ios::binary};
  // Read the original file and write encryption data in the temporary file.
  std::array<unsigned char, g_actualKlen> ibuf{};
  size_t idx1{0};
  size_t immediateMultiple{static_cast<int>(std::ceil(filesize / static_cast<double>(g_actualKlen))) * g_actualKlen};
  for (size_t i{}; i < immediateMultiple / g_actualKlen; ++i)
  {
    ifile.seekg(idx1);
    ifile.read(reinterpret_cast<char*>(ibuf.data()), g_actualKlen);
    std::string temp{};
    temp.reserve(g_actualKlen);
    std::string key{g_actualKey};
    for (size_t i{}; i < g_actualKlen; ++i)
    {
      temp += ibuf[i] xor key[i];
    }
    ofile << temp;
    idx1 += g_actualKlen;
  }
  ofile << kenhash;
  ifile.close();
  ofile.close();
  // Overwrite original file with temporary file.
  fs::rename(fs::path{filename + ".krenqenctemp"}, fs::path{filename.c_str()});
  return true;
}

//
// This would expect only a single valid file and a key. Rules are
// same as the encrypt() function.
//
// Extract the keydata from key filename. Then check the status of
// the file. Check if provided keyhash matches with file keyhash.
// Create temporary file to write decrypted file data. Read encrypted
// file and write decrypted data to temporary file. Replace temporary
// file with original file.
//
bool Krenq::decrypt(const std::string& filename, const std::string& keyname)
{
  this->extract_key(keyname);
  if (!g_kmap.contains(keyname))
    throw std::runtime_error{"Key extraction failed!"};
  Krenq::type_estatus estatus{};
  this->krenq_status(filename, estatus);
  if (!std::get<0>(estatus)) return false;
  std::string ekstrHash{this->get_string_hash(m_kenmap[keyname])};
  std::string fileKeyHash{std::get<3>(estatus)};
  if (ekstrHash != fileKeyHash)
    return false;
  std::fstream ifile{filename, std::ios::in | std::ios::binary};
  std::fstream ofile{filename + ".krenqdectemp", std::ios::out | std::ios::binary};
  std::array<unsigned char, g_actualKlen> fbuf{};
  size_t filesize{std::get<2>(estatus)};
  size_t nIter{(filesize - (32 * 2 + 25)) / g_actualKlen};
  size_t ifpos{32 + 25};
  ifile.seekg(ifpos, std::ios::beg);
  std::string portion{};
  portion.reserve(g_actualKlen);
  for (size_t i{}; i < nIter; ++i)
  {
    ifile.read(reinterpret_cast<char*>(fbuf.data()), g_actualKlen);
    for (size_t j{}; j < g_actualKlen; ++j)
    {
      portion += fbuf[j] xor g_kmap[keyname][j];
    }
    ofile << portion;
    portion = {};
    ifpos += g_actualKlen;
  }
  ifile.close();
  ofile.close();
  fs::rename(fs::path{filename + ".krenqdectemp"}, fs::path{filename.c_str()});
  this->remove_padding(filename);
  m_emap[filename] = keyname;
  return true;
}

//
// This function expects a single valid file. This encrypts the file
// that has been decrypted in the same runtime with the same key.
//
// The process is almost same as encrypt(). The difference is, this
// accesses the key has been extracted by decrypt() and uses it to
// encrypt file.
//
bool Krenq::re_encrypt(const std::string& filename)
{
  Krenq::type_estatus estatus{};
  this->krenq_status(filename, estatus);
  if (std::get<0>(estatus) == true) return false;
  size_t filesize{std::get<2>(estatus)};
  if (filesize == 0) return false;
  std::string filehash{this->get_file_hash(filename)};
  std::string prefix{};
  this->make_prefix(prefix);
  std::string keyname{m_emap[filename]};
  std::string kstr{g_kmap[keyname]};
  std::string kenstr{m_kenmap[keyname]};
  std::string kenhash{this->get_string_hash(kenstr)};
  this->add_padding(filename, filesize);
  std::fstream ofile{filename + ".krenqrcrypttemp", std::ios::out | std::ios::binary};
  ofile << filehash << prefix;
  std::fstream ifile{filename, std::ios::in | std::ios::binary};
  std::array<unsigned char, g_actualKlen> ibuf{};
  size_t idx1{0};
  size_t immediateMultiple{static_cast<int>(std::ceil(filesize / static_cast<double>(g_actualKlen))) * g_actualKlen};
  for (size_t i{}; i < immediateMultiple / g_actualKlen; ++i)
  {
    ifile.seekg(idx1);
    ifile.read(reinterpret_cast<char*>(ibuf.data()), g_actualKlen);
    std::string temp{};
    temp.reserve(g_actualKlen);
    std::string key{g_kmap[keyname]};
    for (size_t i{}; i < g_actualKlen; ++i)
    {
      temp += ibuf[i] xor key[i];
    }
    ofile << temp;
    idx1 += g_actualKlen;
  }
  ofile << kenhash;
  ifile.close();
  ofile.close();
  fs::rename(fs::path{filename + ".krenqrcrypttemp"}, fs::path{filename.c_str()});
  return true;
}

// Encrypt all entries in Krenq.
void Krenq::encrypt_all()
{
  if (!m_keyIsSaved)
  {
    throw std::runtime_error{"Save the key using save_key() before trying to encrypt anything!"};
  }
  for (auto e : m_entries)
  {
    fs::path entry{e};
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
          this->encrypt(fs::path{dfile}.string());
  }
}

// Decrypt all entries in Krenq.
void Krenq::decrypt_all(const std::string& keyname)
{
  for (auto e : m_entries)
  {
    fs::path entry{e};
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

// Re-encrypt all entries in Krenq.
void Krenq::re_encrypt_all()
{
  for (auto e : m_entries)
  {
    fs::path entry{e};
    if (!fs::exists(entry)) continue;
    if (fs::is_regular_file(entry))
    {
      if (!m_emap.contains(entry.string()))
        continue;
      this->re_encrypt(entry.string());
    }
    //
    // If entry is a directory, recurse through it and encrypt all
    // its files.
    //
    else if (fs::is_directory(entry))
      for (auto dfile : fs::recursive_directory_iterator(entry))
        if (fs::is_regular_file(dfile))
        {
          if (!m_emap.contains(fs::path{dfile}.string()))
            continue;
          this->re_encrypt(fs::path{dfile}.string());
        }
  }
}

// Add padding to file to make it multiple of 154 bytes.
void Krenq::add_padding(const std::string& filename, size_t filesize)
{
  std::fstream afile{filename, std::ios::app | std::ios::binary};
  size_t padn{static_cast<int>(std::ceil(filesize / static_cast<double>(g_actualKlen))) * g_actualKlen - filesize};
  std::string padding{};
  padding.reserve(padn);
  for (size_t i{}; i < padn; ++i) padding += 0x1f;
  afile << padding;
  afile.close();
}

// Remove padding from file.
void Krenq::remove_padding(const std::string& filename)
{
  Krenq::type_estatus estatus{};
  this->krenq_status(filename, estatus);
  size_t filesize{std::get<2>(estatus)};
  std::fstream ifile{filename, std::ios::in | std::ios::binary};
  ifile.seekg(filesize - g_actualKlen, std::ios::beg);
  std::array<unsigned char, g_actualKlen> arr{};
  ifile.read(reinterpret_cast<char*>(arr.data()), g_actualKlen);
  size_t padn{0};
  for (auto iter{arr.rbegin()}; iter != arr.rend(); ++iter)
  {
    if (*iter != 0x1f) break;
    if (*iter == 0x1f) ++padn;
  }
  size_t new_filesize{filesize - padn};
  ifile.close();
  fs::resize_file(fs::path{filename}, new_filesize);
}

// Extract key from key file.
void Krenq::extract_key(const std::string& keyname)
{
  if (g_kmap.contains(keyname)) return;
  std::fstream ifile{keyname, std::ios::in | std::ios::binary};
  ifile.seekg(0, std::ios::end);
  if (ifile.tellg() != g_encryptedKlen)
    throw std::runtime_error{"Invalid key!"};
  ifile.seekg(0, std::ios::beg);
  Key* providedKey{new Key{}};
  std::string extractedKey{};
  extractedKey.reserve(g_actualKlen);
  ifile.read(reinterpret_cast<char*>(providedKey), sizeof(Key));

  extractedKey += std::to_string(providedKey->s_kid);
  extractedKey += providedKey->s_ksport1;
  extractedKey += std::to_string(providedKey->s_rt1);
  extractedKey += providedKey->s_ksport2;
  extractedKey += std::to_string(providedKey->s_rt2);
  extractedKey += providedKey->s_ksport3;
  extractedKey += std::to_string(providedKey->s_rt3);
  extractedKey += providedKey->s_ksport4;
  extractedKey += std::to_string(providedKey->s_rt4);

  size_t diff{g_actualKlen - extractedKey.length()};
  extractedKey += extractedKey.substr(0, diff);

  g_kmap[keyname] = extractedKey;
  ifile.close();
  std::fstream ikey{keyname, std::ios::in | std::ios::binary};
  std::string ekstr{};
  std::array<unsigned char, 32> arr{};
  ikey.read(reinterpret_cast<char*>(arr.data()), 32);
  for (auto c : arr) ekstr += c;
  m_kenmap[keyname] = ekstr;
  ikey.close();
  delete providedKey;
}


