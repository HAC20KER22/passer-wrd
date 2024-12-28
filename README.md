# passer-wrd

This a python tool to crack password hashes.
It currently supports:
1. MD5
2. bcrypt
3. SHA-1
4. SHA - 256
5. SHA - 512
6. argon2
7. 

This tool takes full advantage of the power of the python libraries. 
To download these tools you need the following libraries

1. hashlib - already downloaded
2. pyfiglet 
3. bcrypt
4. termcolor
5. threading - already downloaded
6. concurrent.futures - already downloaded

Downloading libraries:

``` 
python3 -m pip install bcrypt
```
```
python3 -m pip install pyfiglet
```
``` 
python3 -m pip install termcolor
```

If you want to add a hashing algorithm to that you also need to change
1. function check_type_of_hash - Here you need to get the defining factor of the hash
2. function process_chunk in the class Compute_hash to compute the hash by adding another elif condition for the hash_type
3. also add a text file for the computed hash to act as cache.

 
