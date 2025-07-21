import os
from langchain_community.document_loaders import JSONLoader
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import ChatOpenAI
from langchain.chains.question_answering import load_qa_chain
from dotenv import load_dotenv
import json
from langchain.schema import Document

# Load .env for OpenAI API key
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY not set in .env file")


# Prompt user
print("What type of log data would you like to summarize?")
print("1. Brute Force Only")
print("2. Web Attacks Only")
print("3. Both")
choice = input("Enter 1/2/3: ").strip()

paths = []
if choice == "1":
    paths = ["output/brute_force.json"]
elif choice == "2":
    paths = ["output/web_attacks.json"]
elif choice == "3":
    paths = ["output/brute_force.json", "output/web_attacks.json"]
else:
    print("❌ Invalid choice. Exiting.")
    exit()

# Load JSON content
combined_data = []
for path in paths:
    if os.path.exists(path):
        with open(path, 'r') as f:
            print(f"✅ Loaded {path}")
            combined_data.extend(json.load(f))
    else:
        print(f"⚠️ Warning: {path} not found. Skipping.")
          
if not combined_data:
    print("❌ No valid data found to summarize. Exiting.")
    exit()


# Convert JSON to documents for LangChain
documents = [Document(page_content=str(entry)) for entry in combined_data]
    
splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
docs = splitter.split_documents(documents)

# Load LLM and QA Chain
llm = ChatOpenAI(model="gpt-4o",openai_api_key=api_key, temperature=0)
chain = load_qa_chain(llm, chain_type="stuff")

# Ask for a summary
query = "Summarise the findings from both the brute-force and web attack logs. Highlight suspicious IPs and any patterns."
response = chain.run(input_documents=docs, question=query)

# Output the summary
print("\nSecurity Findings Summary:\n")
print(response)
