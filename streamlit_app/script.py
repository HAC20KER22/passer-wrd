import streamlit as st
from index import check_type_of_hash, parallel_hash_cracker, cache_calling
import time

st.set_page_config(page_title="Passer-wrd", page_icon="🔓")

st.title("🔓 Passer-wrd")

# FIX: Label provided with label_visibility="collapsed" to prevent warning
input_hash = st.text_input("Enter Hash", placeholder="Enter the Hash", label_visibility="collapsed")

st.subheader("Performance Table")

table = """
| No. of Threads      | 10  | 100  | 1000  | 10000  |
|---------------------|-----|------|-------|--------|
| Factor by which time can be reduced | 10  | 50-90 | 500-900 | <10000 |
"""
st.markdown(table)

st.subheader("**Advice (Minimum Number of Threads)**")
advice = """
- **MD5/SHA1/SHA256/SHA512/NTLM** → 100  
- **BCRYPT** → 1000  
- **ARGON2** → 1000  
"""
st.markdown(advice)

threads = st.number_input("Number of Threads", min_value=10, max_value=10000, value=100)
wordlist_file = st.file_uploader("Upload a wordlist file:", type=["txt"])

if st.button("Crack Hash") and input_hash:
    start_time = time.time()  
    
    hash_type = check_type_of_hash(input_hash)
    if hash_type == "unknown":
        st.error("Unsupported hash type!")
        elapsed_time = time.time() - start_time 
        st.markdown(f"**Time Taken:** {elapsed_time:.2f} seconds")
    else:
        st.write(f"**Detected hash type:** {hash_type}")
        
        # Check cache before computing
        cached_result = cache_calling(hash_type, input_hash)
        if cached_result:
            elapsed_time = time.time() - start_time
            st.success(f"Password Found (Cached): {cached_result}")
            st.markdown(f"**Time Taken:** {elapsed_time:.2f} seconds")
        elif wordlist_file:
            wordlist = wordlist_file.getvalue().decode("MacRoman").splitlines()

            with st.spinner("Cracking the hash..."):
                start_time = time.time()  
                result = parallel_hash_cracker(hash_type, input_hash, threads, wordlist)
                elapsed_time = time.time() - start_time 

                if result:
                    st.success(f"Password Found: {result}")
                else:
                    st.error("Password not found in the given wordlist.")
                st.markdown(f"**Time Taken:** {elapsed_time:.2f} seconds")
