import streamlit as st
from index import check_type_of_hash, parallel_hash_cracker

st.set_page_config(page_title="Passer-wrd", page_icon="🔓")

st.title("🔓 Passer-wrd")


input_hash = st.text_input("", placeholder="Enter the Hash")
st.subheader("Performance Table")

# Creating a table using Markdown
table = """
| No. of Threads      | 10  | 100  | 1000  | 10000  |
|---------------------|-----|------|-------|--------|
| Factor by which time can be reduced | 10  | 50-90 | 700-900 | <10000 |

"""
st.markdown(table)
st.subheader("**Advice (Minimum Number of Threads)**")
advice = """
- **MD5/SHA1/SHA256/SHA512/NTLM** → 100  
- **BCRYPT** → 1000  
- **ARGON2** → 1000  
"""

st.markdown(advice)
threads = st.number_input("Enter the number of Threads", min_value=10, max_value=10000, value=100)
wordlist_file = st.file_uploader("Upload a wordlist file:", type=["txt"])


if st.button("Crack Hash") and input_hash:
    hash_type = check_type_of_hash(input_hash)
    if hash_type == "unknown":
        st.error("Unsupported hash type!")
    else:
        st.write(f"Detected hash type: {hash_type}")
        if wordlist_file:
            wordlist = wordlist_file.getvalue().decode("MacRoman").splitlines()
            with st.spinner("Cracking the hash..."):
                result = parallel_hash_cracker(hash_type, input_hash, threads, wordlist)
                if result:
                    st.success(f"Password Found: {result}")
                else:
                    st.error("Password not found in the given wordlist.")
