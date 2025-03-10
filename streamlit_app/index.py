import hashlib
import bcrypt
from queue import Queue
from threading import Thread, Event
import concurrent.futures
from argon2 import PasswordHasher
from passlib.hash import nthash
import os
import streamlit as st

def check_type_of_hash(r_hash):
    if len(r_hash) == 32:
        is_system_hash = st.radio("Is this a system hash?", ["Yes", "No"], index=1)
        return "ntlm" if is_system_hash == "Yes" else "md5"
    elif len(r_hash) == 64:
        return 'sha256'
    elif len(r_hash) == 40:
        return 'sha1'
    elif len(r_hash) == 128:
        return 'sha512'
    elif r_hash.startswith("$2") and len(r_hash) == 60:
        return "bcrypt"
    elif r_hash.startswith("$argon"):
        return "argon2"
    return "unknown"

def cache_calling(hash_type, hash_received):
    cache_file = hash_type + ".txt"
    if not os.path.exists(cache_file):
        return None
    with open(cache_file, "r") as file_obj:
        for line in file_obj:
            stored_hash, password = line.strip().split(":")
            if stored_hash == hash_received:
                return password
    return None

def compute_hash(hash_type, hash_received, wordlist, stop_event):
    for word in wordlist:
        if stop_event.is_set():
            return None
        word = word.strip()
        if hash_type == "md5" and hashlib.md5(word.encode()).hexdigest() == hash_received:
            return word
        elif hash_type == "sha1" and hashlib.sha1(word.encode()).hexdigest() == hash_received:
            return word
        elif hash_type == "sha256" and hashlib.sha256(word.encode()).hexdigest() == hash_received:
            return word
        elif hash_type == "sha512" and hashlib.sha512(word.encode()).hexdigest() == hash_received:
            return word
        elif hash_type == "bcrypt" and bcrypt.checkpw(word.encode(), hash_received.encode()):
            return word
        elif hash_type == "argon2":
            try:
                if PasswordHasher().verify(hash_received, word):
                    return word
            except:
                pass
        elif hash_type == "ntlm" and nthash.hash(word) == hash_received:
            return word
    return None

def parallel_hash_cracker(hash_type, hash_received, threads, wordlist):
    cached_password = cache_calling(hash_type, hash_received)
    if cached_password:
        return cached_password
    
    stop_event = Event()
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(compute_hash, hash_type, hash_received, wordlist[i::threads], stop_event) for i in range(threads)]
        for future in concurrent.futures.as_completed(futures):
            result = future.result()
            if result:
                stop_event.set()
                with open(hash_type + ".txt", "a") as file:
                    file.write(f"{hash_received}:{result}\n")
                with open(hash_type + ".txt", "a") as file:
                    file.write(f"{hash_received}:{result}")
                return result
    return None
