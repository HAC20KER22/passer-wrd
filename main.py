import hashlib
import pyfiglet
from queue import Queue
from termcolor import colored
from threading import *
from time import *
import sys
import re

class Cache(Thread):
    def __init__(self,hash_received,algo,shared_var):
        super().__init__()
        self.r_hash = hash_received
        self.path = "./" + algo + ".txt"
        self.shared = shared_var
    def run(self):
        file_obj = open(self.path,"a")
        i = file_obj.readline().strip()
        while i:
            c_hash,password = i.split(":")
            if c_hash == self.r_hash:
                self.shared.put(password)
                break
            i = file_obj.readline().strip
        file_obj.close()
        self.shared.put("not found")



class MD5(Thread):
    def __init__(self,hash_received,shared_variable_password): # to declare variables
        super().__init__()
        self.hash_received = hash_received # hash received by the user
        self.shared = shared_variable_password # store the password if found or not found
    def run(self):
        file_obj = open("./rockyou.txt","r")
        i = file_obj.readline().strip()
        while i:
            if hashlib.md5(i.encode()).hexdigest() == self.hash_received:
                self.shared.put(i)
                break
            i = file_obj.readline().strip()
        file_obj.close()
        self.shared.put("not found")



def check_type_of_hash(r_hash):
    ans = ""
    if len(r_hash) == 32:
        ans = "md5"
    elif len(r_hash) == 256:
        ans = 'sha-256'
    elif len(r_hash) == 40:
        ans = 'sha-1'
    elif len(r_hash) == 512:
        ans = 'sha-512'
    elif r_hash[0:2]=='$2' and len(r_hash) == 60:
        ans = "bcrypt"
    
    return ans

      


if __name__ == "__main__":
    banner = colored(pyfiglet.figlet_format("passer-wrd",font="slant"),"red")
    print(banner)
    sleep(2)
    input_hash = input(colored("\033[1m"+"Enter the hash in hex format: ","green")) # \033[1m is for bold text

    hash_type = check_type_of_hash(input_hash)
    if hash_type == "":
        print("Sorry the hash you have provided is currently not supported by this tool.")
        sys.exit(0)

    flag =  False
    # MD5 hash checking 
    if hash_type == "can't resolve":
        print()
    elif hash_type == 'md5':
        shared_password = Queue() # declaring the Queue object to store the value from the thread
        
        #   Checking in cache
        obj_cache = Cache(input_hash,hash_type,shared_password)
        obj_cache.start()
        obj_cache.join()
        password = shared_password.get()
        if password != "not found":
            print("The hash was already computed!\n The password is",shared_password)
            sys.exit(0)

        #    Computing the hash now
        shared_password = Queue()
        obj_md5 = MD5(input_hash,shared_password)
        obj_md5.start() # calling start fuction in thread module
        obj_md5.join() # joining the thread here
        password = shared_password.get() # this is to get the password from the shared Queue object
        if password != 'not found':
            print("\n\n","Password Found: ",password,sep="")
            sys.exit(0)
        else:
            flag = False


