/**
 * Krenq - Universal file encryptor written in C++ 20
 * Copyright (c) 2024 Hossain Md. Fahim <hossainmdfahim66@gmail.com>
 * Licensed under the GNU General Public License v3.0 (GPL-3.0)
 * See the LICENSE file for more information.
 */
#include "krenq/Core.hxx"
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <ios>
#include <random>
#include <sstream>

// Return string hash.
std::string Krenq::get_string_hash(const std::string& strn)
{
  struct Sha_256 sha_256;
  std::array<std::uint8_t, 32> sha256Hash{};
  sha_256_init(&sha_256, sha256Hash.data());
  sha_256_write(&sha_256, strn.c_str(), std::strlen(strn.c_str()));
  sha_256_close(&sha_256);
  std::string sha256HashString{};
  sha256HashString.reserve(32);
  for (auto e : sha256Hash) sha256HashString += e;
  return sha256HashString;
}

// Return file hash.
std::string Krenq::get_file_hash(const std::string& filename)
{
  std::fstream ifile{filename, std::ios::in | std::ios::binary};
  std::stringstream iss;
  iss << ifile.rdbuf();
  std::string filedata{iss.str()};
  struct Sha_256 sha_256;
  std::array<std::uint8_t, 32> sha256Hash{};
  sha_256_init(&sha_256, sha256Hash.data());
  sha_256_write(&sha_256, filedata.c_str(), std::strlen(filedata.c_str()));
  sha_256_close(&sha_256);
  std::string sha256HashString{};
  sha256HashString.reserve(32);
  for (auto e : sha256Hash) sha256HashString += e;
  ifile.close();
  return sha256HashString;
}

// Return random string of specified null-terminated string and
// optionally using bytes from specified string.
std::string Krenq::get_random_string(size_t len, const std::string& providedCharDB)
{
  /** Internal `char` database to create string from. */
  std::string charDB{"(D}He{nw<pJA_|Lkcb1d?IfWV2Pym;0%*qNQ\\Gv8u4Bt]l[T$CiSa,zXh'rK6/!O5>=)3YxjZ7+@&sg.R-FU^:M#E9o\""};
  if (providedCharDB.length() != 0) charDB = providedCharDB;

  /** Generate random string of length `len`. */
  std::string random_string{};
  random_string.reserve(len);
  for (size_t i{}; i < len - 1; ++i)
  {
    random_string += charDB[this->get_randomN_from_limit(0, charDB.length() - 1)];
  }
  return random_string;
}

// Return random number within limit.
long long Krenq::get_randomN_from_limit(long long u, long long v)
{
  if (u > v) std::swap(u, v);
  std::random_device rd;
  std::mt19937 gen{rd()};
  std::uniform_int_distribution<> dist(u, v);
  return dist(gen);
}

// Return little-endian format of 32-bit uint.
std::uint32_t Krenq::uint32_to_LittleEndian(std::uint32_t value)
{
  //If the system is little endian, no need to convert.
  if (std::endian::native == std::endian::little) return value;
  std::uint32_t LEval
  {
    (value & 0xff000000) >> 24 |
    (value & 0x00ff0000) >> 8 |
    (value & 0x0000ff00) << 8 |
    (value & 0x000000ff) << 24
  };
  return LEval;
}

// Return little-endian format of 64-bit uint.
std::uint64_t Krenq::uint64_to_LittleEndian(std::uint64_t value)
{
    // If the system is little endian, no need to convert.
    if (std::endian::native == std::endian::little) return value;
    std::uint64_t LEval
    {
        (value & 0xff00000000000000) >> 56 |
        (value & 0x00ff000000000000) >> 40 |
        (value & 0x0000ff0000000000) >> 24 |
        (value & 0x000000ff00000000) >> 8  |
        (value & 0x00000000ff000000) << 8  |
        (value & 0x0000000000ff0000) << 24 |
        (value & 0x000000000000ff00) << 40 |
        (value & 0x00000000000000ff) << 56
    };
    return LEval;
}

// Filter indexes of Krenq entries.
void Krenq::filter_indexes(std::vector<int>& vidx)
{
  int lim{static_cast<int>(m_entries.size())};
  // Remove duplicate indexes.
  std::sort(vidx.begin(), vidx.end());
  vidx.erase(std::unique(vidx.begin(), vidx.end()), vidx.end());
  // Remove indexes that are bigger and smaller than m_entries index size.
  auto iter{std::remove_if(vidx.begin(), vidx.end(), [lim](int x){ return (x < 1 or x > lim); })};
  vidx.erase(iter, vidx.end());
}

std::string Krenq::getLocalDatetime()
{
  auto now{std::chrono::system_clock::now()};
  std::time_t now_time{std::chrono::system_clock::to_time_t(now)};
  std::tm* local_tm = std::localtime(&now_time);
  std::stringstream ss;
  ss << std::put_time(local_tm, "(%Y-%m-%d %H:%M:%S)");
  return std::string{ss.str()};
}


