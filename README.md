# Krenq - Universal File Encryptor
This is Krenq, universal file encryptor library written in C++ 20 with no external dependency.

## Usage:

### Include header:
```
#include "krenq/Core.hxx"
```
### Initialize Krenq:
```
// Construct Krenq with any number of files or directories.
// These are called entries.
Krenq k{"file1", "dir1"};
```
### Save the auto-generated key:
```
// The key file name must be unique.
k.save_key("key1.krenq");
```
### Encrypt:
You can encrypt all entries together.
```
k.encrypt_all();
```
Or you can encrypt entries by index (starts from 1).
```
k.encrypt_by_index(1, 2);
```
### Decrypt:
You can decrypt all entries together.
```
// Provide the key to decrypt.
k.decrypt_all("key1.krenq");
```
Or you can decrypt entries by index (starts from 1).
```
k.decrypt_by_index("key1.krenq", 1, 2);
```
### Re-encrypt:
You can decrypt encrypted files and re-encrypt them on the fly using the same key automatically.
```
// Re-encryption wouldn't be possible without successfully decrypting the entry first.
k.decrypt_by_index("key1.krenq", 2);
// Do stuffs here with the file in index 2.
// Re-encrypt it.
k.re_encrypt_by_index(2);
```
You can re-encrypt all too.
```
k.decrypt_all("key1.krenq");
k.re_encrypt_all();
```

## How it works:
Krenq manipulates the bytes of files. As simple as that.
## Installation:
### Linux:
Clone the repo and `cd` into it. Create a build directory and run cmake from it.
```
git clone https://github.com/MetalInMyVeins/krenq
cd krenq
mkdir -p build
cd build
cmake ..
make
```
This would create a dynamically linked shared object file `libkrenq.so` in `lib/` folder. You can put this shared object anywhere to use in your program. For ease of use, put `include/krenq/` in a known include path and libkrenq.so in a known linker path of your environment.

If you want to test Krenq locally just right away, create a directory called `test/`. Copy `include/krenq/` and `lib/libkrenq.so` in `test/`. Create a C++ program `main.cxx` which could be like this:

```
#include "krenq/Core.hxx"
#include <iostream>

int main()
{
  Krenq k{"file1", "dir1"};
  std::cout << k.get_entry_size();
  return 0;  
}
```
So `test/` now contains 'krenq/', `libkrenq.so`, and `main.cxx`. Compile `main.cxx` like this:
```
g++ -std=c++20 main.cxx -o binary -lkrenq -L. -Wl,-rpath=.
```
So in this way, `binary` would be dependent on `libkrenq.so` of current directory in runtime. Execute `binary` to see the result.

## Notes:
- Construction of Krenq is flexible. You can construct it with any number of strings. In Krenq wording, these are called entries. Krenq would automatically filter entries. If an entry is a directory, krenq would recurse through it.
- Krenq would throw a runtime error if you try to encrypt anything without saving the auto-generated key first.
- All Krenq keys would have the ".krenq" extension automatically even if you do not provide it.
- Krenq does not overwrite any keys. Instead, it throws runtime error in naming conflict. All key file names must be unique.
- If you have an encrypted file but lost the key, consider the file lost as well.
- A key is considered alive as long as there are encrypted files that had been encrypted with it. If there are no files left that were encrypted with that key, the key is considered dead as it cannot be used to encrypt anything anymore. Fresh encryption is only possible using auto-generated key.
- An encrypted file can be decrypted and re-encrypted (with the same key automatically) only in the same runtime.
- Any manipulation to an encrypted file would render it non-decryptable. Same goes for the key files.
- Krenq would not encrypt an already encrypted file or decrypt an already decrypted file.
- It's safe to try to decrypt files with any key.

## To Do:
- A logger that keeps track of detailed encryption and decryption information per runtime.
- Users should be able to directly load the decrypted state of encrypted files in memory depending on available system memory.

## License:
See the `LICENSE` file for licensing information.


