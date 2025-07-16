import json
import argparse
from langchain_core.documents import Document
from langchain.chat_models import ChatOpenAI
from langchain.chains import load_qa_chain


def load_json(filepath):
    with open(filepath, "r") as f:
        return json.load(f)


def convert_to_documents(auth_data, access_data):
    docs = []

    for ip, count in auth_data:
        text = f"IP {ip} had {count} failed login attempts (possible brute-force attack)."
        docs.append(Document(page_content=text, metadata={"type": "brute_force", "ip": ip}))

    for ip, reason, path in access_data:
        text = f"IP {ip} triggered {reason} on path {path}."
        docs.append(Document(page_content=text, metadata={"type": "web_attack", "ip": ip, "reason": reason}))

    return docs


def main(mode, question):
    # Load exported detections
    auth_data = load_json("output/auth_suspects.json")
    access_data = load_json("output/access_suspects.json")

    docs = convert_to_documents(auth_data, access_data)

    # Load LLM
    llm = ChatOpenAI(model="gpt-3.5-turbo", temperature=0)
    chain = load_qa_chain(llm, chain_type="stuff")

    if mode == "summary":
        query = "Summarize the suspicious activity in the logs."
    elif mode == "question":
        query = question
    else:
        raise ValueError("Mode must be 'summary' or 'question'")

    response = chain.run(input_documents=docs, question=query)
    print("\nResult:\n" + response)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Summarize or query security log findings.")
    parser.add_argument("--mode", choices=["summary", "question"], required=True, help="Mode of interaction")
    parser.add_argument("--q", type=str, default="", help="Custom question for 'question' mode")
    args = parser.parse_args()

    main(args.mode, args.q)