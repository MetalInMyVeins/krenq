/**
 * Krenq - Universal file encryptor written in C++ 20
 * Copyright (c) 2024 Hossain Md. Fahim <hossainmdfahim66@gmail.com>
 * Licensed under the GNU General Public License v3.0 (GPL-3.0)
 * See the LICENSE file for more information.
 */
#include "krenq/Core.hxx"
#include <filesystem>
#include <fstream>
#include <stdexcept>
#include <string>

namespace fs = std::filesystem;

//
// Firstly, copies of the same key in different key filenames
// shouldn't be possible. So prevent that first.
//
// Keys have ".krenq" extension. Existence of key without .krenq
// extension should be considered impossible. So if user has
// modified any Krenq keyname, that's not Krenq's business. Krenq
// would would count .krenq extension as a valid key.
//
// If keyname doesn't have a .krenq extension, add it. keyname <= 6
// cannot have a .krenq extension, so add it without hesitation. If
// keyname > 6, it might have .krenq. So check if it does have. If
// not, add it.
//
// Once the valid keyname is generated, we should check if key of
// the same name already exists in the same path or not. If it
// doesn't, we can proceed. And if it does, we should throw an
// exception and terminate the program hehe.
//
void Krenq::save_key(const std::string& keyname)
{
  if (m_keyIsSaved == true)
  {
    std::cout << "Copies of same key cannot be generated even in different files!";
    return;
  }
  std::string mainKey{};
  if (keyname.length() <= 6) mainKey += keyname + ".krenq";
  else if (keyname.length() > 6)
  {
    std::string ext{keyname.substr(keyname.length() - 6, 6)};
    if (ext != ".krenq") mainKey += ".krenq";
  }
  else mainKey = keyname;

  fs::path p{mainKey};
  if (fs::exists(p)) throw std::runtime_error{"Key already exists! Choose a unique name!"};
  m_keyname = mainKey;
  std::fstream ofile{m_keyname, std::ios::out | std::ios::binary};
  ofile << m_encryptedKey;
  ofile.close();
  m_keyIsSaved = true;
}


