import hashlib
import pyfiglet
import bcrypt
from queue import Queue
from termcolor import colored
from threading import *
from time import *
import sys
import re
import time
import concurrent.futures
from argon2 import PasswordHasher
import os
from passlib.hash import nthash

class Cache(Thread):
    def __init__(self, hash_received, hash_type, shared_var):
        super().__init__()
        self.r_hash = hash_received
        self.path = hash_type + ".txt"
        if not os.path.exists(self.path):
            with open(self.path, 'w') as file:
                pass
        self.shared = shared_var
    
    def run(self):
        with open(self.path, "r") as file_obj:
            i = file_obj.readline().strip() # Twice because the first line is an empty string that's being appended 
            i = file_obj.readline().strip()
            while i:
                c_hash, password = i.split(":")
                if c_hash == self.r_hash:
                    self.shared.put(password)
                    break 
                
                i = file_obj.readline().strip()  # Read next line and strip
        self.shared.put("not found")

class Compute_hash(Thread):
    def __init__(self, hash_type, hash_received, shared_variable_password, stop_event, threads):
        super().__init__()
        self.hash_received = hash_received
        self.hash_type = hash_type
        self.shared = shared_variable_password
        self.stop_event = stop_event
        self.threads = threads
        if self.hash_type == "argon2":
            regex = r"\$argon2id\$v=(\d+)\$m=(\d+),t=(\d+),p=(\d+)"
            match = re.search(regex, self.hash_received)

            if match:
                m = int(match.group(2))  # Memory cost 
                t = int(match.group(3))  # Time cost 
                p = int(match.group(4))  # Parallelism factor 
                self.ph = PasswordHasher(time_cost=t, memory_cost=m, parallelism=p)
            else:
                print("\nThis is not a valid Argon 2 hash. Kindly confirm it and try again.")
                sys.exit(0)
        
    def process_chunk(self, lines):
        for i in lines:
            if self.stop_event.is_set():
                return
            
            i = i.strip()
            if self.hash_type == "md5":
                if hashlib.md5(i.encode()).hexdigest() == self.hash_received:
                    self.shared.put(i) 
                    self.stop_event.set()
                    return
            elif self.hash_type == "bcrypt":
                salt = self.hash_received[:29:].encode()
                if bcrypt.checkpw(i.encode(), salt + self.hash_received[29:].encode()):
                    self.shared.put(i)
                    self.stop_event.set()
                    return
            elif self.hash_type == "sha1":
                if hashlib.sha1(i.encode()).hexdigest() == self.hash_received:
                    self.shared.put(i)
                    self.stop_event.set()
                    return
            elif self.hash_type == "sha256":
                if hashlib.sha256(i.encode()).hexdigest() == self.hash_received:
                    self.shared.put(i)
                    self.stop_event.set()
                    return
            elif self.hash_type == "sha512":
                if hashlib.sha512(i.encode()).hexdigest() == self.hash_received:
                    self.shared.put(i)
                    self.stop_event.set()
                    return
            elif self.hash_type == "argon2":
                if self.ph.verify(self.hash_received, i):
                    self.shared.put(i)
                    self.stop_event.set()
                    return
            elif self.hash_type == "ntlm":
                if nthash.hash(i) == self.hash_received:
                    self.shared.put(i)
                    self.stop_even.set()
                    return

    def run(self):
        with open("short.txt", "r", encoding="MacRoman") as file_obj:
            lines = file_obj.readlines()

        chunk_size = len(lines) // self.threads
        chunks = [lines[i: i + chunk_size] for i in range(0, len(lines), chunk_size)]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = [executor.submit(self.process_chunk, chunk) for chunk in chunks]
            concurrent.futures.wait(futures)

        self.shared.put("not found")

def check_type_of_hash(r_hash):
    if len(r_hash) == 32:
        if (input("Is this a system hash (Y/n): ")) == "Y":
            return "ntlm"
        return "md5"
    elif len(r_hash) == 64:
        return 'sha256'
    elif len(r_hash) == 40:
        return 'sha1'
    elif len(r_hash) == 128:
        return 'sha512'
    elif r_hash[0:2] == '$2' and len(r_hash) == 60:
        return "bcrypt" 
    elif r_hash.startswith("$argon"):
        return "argon2"
    return ""

def cache_calling(hash_type, hash_received, shared_password):
    obj_cache = Cache(hash_received, hash_type, shared_password)
    obj_cache.start()
    obj_cache.join()
    password = shared_password.get()
    if password != "not found":
        print("\n\nThe hash was already computed! \nThe password is", colored("\033[1m" + password, "green"))
        return True
    return False

def loading(stop_event):
    l = ["\\", "|", "/", "-"]
    k = 0
    while not stop_event.is_set():
        print("Calculating... " + "\033[?25l" + l[k], end="", flush=True)
        time.sleep(0.1)
        print("\r", end="", flush=True)
        k = (k + 1) % 4
    
    print("\r" + " " * 20, end="", flush=True)  # Clear the line
    print("\r", end="", flush=True)  # Move to the next line
    print("\033[?25h")


def calculating_hash(hash_type, input_hash, shared_password, stop_event, input_threads):
    shared_password = Queue()
    stop_event = Event()
    start_time = time.time()
    obj = Compute_hash(hash_type, input_hash, shared_password, stop_event, input_threads)
    obj.start()

    loading_thread = Thread(target=loading, args=(stop_event,))
    loading_thread.start()

    obj.join()
    stop_event.set()
    end_time = time.time()
    password = shared_password.get()
    if password != "not found":
        print("\n\nPassword Found: ", "\033[1m" + colored(password, "green"), sep="")
        print("\nCalculated the password in ","\033[1m"+colored((end_time - start_time),"green"),sep="")
        f = open(hash_type + ".txt", "a+")
        f.write("\n" + input_hash + ":" + password)
        f.close()
    else:
        print("\n\nSorry!! Password was not found.")


if __name__ == "__main__":
    banner = colored(pyfiglet.figlet_format("passer-wrd", font="slant"), "red")
    print(banner,end="")
    print(colored("                 Created by: HACK20KER22\n","cyan"))
    sleep(2)
    choice = "Y"
    while choice=="Y":
        input_hash = input(colored("\033[1m" + "Enter the hash in the standard format: ", "green")) # \033[1m is for bold text
        print(open("banner.txt").read(), end="")
        print("\n")
        print(colored("You need to understand that just increasing the number of threads won't guarantee a faster result, \n As the number of threads the time to change between threads will also increase. ","red"))
        input_threads = int(input(colored("\033[1m" + "Enter the number of threads [100 .. 10000] (default = 100): ","green"))) 
        if input_threads < 10:
            input_threads = 100

        # Checking Hash Type
        hash_type = check_type_of_hash(input_hash)
        if hash_type == "":
            print("\nSorry the hash you have provided is currently not supported by this tool.")
            sys.exit(0)

        print("\nFigured out the hash: " + hash_type)

        shared_password = Queue()
        flag = cache_calling(hash_type, input_hash, shared_password)
         
        if not flag:
            print("\nCannot find in cache.")
            # Start the hash calculation with the loading spinner
            calculating_hash(hash_type, input_hash, shared_password, Event(), input_threads)
        else:
            choice = input("\n\nTo enter another hash (Y/n): ")

    print("\n\n GoodBye!! \U0001F44B")
    print("\n This session will end in 10 seconds")
    sleep(10)
