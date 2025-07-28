import os
from pathlib import Path
import chainlit as cl
from dotenv import load_dotenv
from langchain.docstore.document import Document
from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_openai import ChatOpenAI
from langchain.chains.combine_documents import create_stuff_documents_chain
from langchain_core.prompts import PromptTemplate
import pprint

# Import parser and detector modules
from auth_log_parser import parse_auth_log_line
from access_log_parser import parse_access_log_line
from detectors.bf_detector import detect_brute_force
from detectors.web_attack_detector import detect_web_attacks
from detectors.intrusion_detector import detect_intrusions
from detectors.user_enum_detector import detect_user_enumeration
from detectors.port_scan_detector import detect_port_scans
from detectors.suspicious_http_detector import detect_suspicious_http_methods
from detectors.dos_detector import detect_dos_attempts

# Load environment variables
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
if not api_key:
    raise ValueError("OPENAI_API_KEY not set in .env file")

# Setup LLM and prompt globally
llm = ChatOpenAI(model="gpt-4o", openai_api_key=api_key, temperature=0)
prompt = PromptTemplate.from_template(
    """You are a helpful and friendly cybersecurity assistant for small business owners.

You will be given findings extracted from system log files that may indicate suspicious activity, such as failed login attempts, unusual IP addresses, or web-based attacks.

Your job is to:
1. Clearly explain what happened in plain, non-technical language.
2. Summarize which IP addresses or users were involved and what they were trying to do.
3. Identify whether each type of activity is low, medium, or high risk.
4. Suggest clear, simple next steps for a small business owner with limited technical expertise (e.g. block IP, reset password, talk to IT support).
5. Reassure the user if no serious issues were found.

Avoid technical jargon. Write as if you're explaining this to someone managing their business without a cybersecurity team.

Context:
{context}

Question: {question}
Answer:"""
)

chain = create_stuff_documents_chain(llm, prompt)

docs = []

@cl.on_chat_start
async def start():
    await cl.Message(
        "👋 Welcome! You can tell me about your business context if you'd like (e.g. 'I run an online retail store').\n\nType 'upload logs' to start analyzing your `.log` files."
    ).send()

@cl.on_message
async def answer(message: cl.Message):
    content = message.content.strip().lower()

    if content == "upload logs":
        await cl.Message("📥 Please upload your `auth.log` and/or `access.log` files for analysis.").send()

        files = await cl.AskFileMessage(
            content="Upload `.log` files for brute-force and web attack analysis:",
            accept=[".log"],
            max_size_mb=5,
            max_files=5
        ).send()

        await cl.Message("📄 Reading uploaded files...").send()

        auth_entries = []
        access_entries = []
        auth_uploaded = False
        access_uploaded = False
        auth_suspects = []
        intrusion_suspects = []
        user_enum_suspects = []
        access_suspects = []
        port_scan_suspects = []
        http_suspects = []
        dos_suspects = []

        for file in files:
            with open(file.path, "r", encoding="utf-8") as f:
                content = f.read()
            lines = content.splitlines()

            if "sshd" in content or "authentication failure" in content:
                auth_uploaded = True
                await cl.Message(f"🔍 Parsing `{file.name}` as SSH/auth log...").send()
                for line in lines:
                    parsed = parse_auth_log_line(line)
                    if parsed:
                        auth_entries.append(parsed)
            elif "GET" in content or "POST" in content:
                access_uploaded = True
                await cl.Message(f"🔍 Parsing `{file.name}` as web access log...").send()
                for line in lines:
                    parsed = parse_access_log_line(line)
                    if parsed:
                        access_entries.append(parsed)

        if auth_uploaded:
            await cl.Message("Running brute-force detection...").send()
            auth_suspects = detect_brute_force(entries=auth_entries) if auth_entries else []
            if auth_suspects:
                await cl.Message(f"🚨 Brute-force activity detected from {len(auth_suspects)} IP addresses.").send()
            else:
                await cl.Message("✅ No brute-force activity detected.").send()

            await cl.Message("Running intrusion detection...").send()
            intrusion_suspects = detect_intrusions(auth_entries) if auth_entries else []
            if intrusion_suspects:
                await cl.Message(f"🚨 Intrusion attempts detected from {len(intrusion_suspects)} IP addresses.").send()
            else:
                await cl.Message("✅ No intrusion attempts detected.").send()

            await cl.Message("Running user enumeration detection...").send()
            user_enum_suspects = detect_user_enumeration(auth_entries) if auth_entries else []
            if user_enum_suspects:
                await cl.Message(f"🚨 User enumeration detected from {len(user_enum_suspects)} IP addresses.").send()
            else:
                await cl.Message("✅ No user enumeration detected.").send()

        if access_uploaded:
            await cl.Message("Running web attack detection...").send()
            access_suspects = detect_web_attacks(entries=access_entries) if access_entries else []
            if access_suspects:
                await cl.Message(f"🚨 Web attacks detected from {len(access_suspects)} IP addresses.").send()
            else:
                await cl.Message("✅ No web attack patterns detected.").send()

            await cl.Message("Running port scan detection...").send()
            port_scan_suspects = detect_port_scans(entries=access_entries) if access_entries else []
            if port_scan_suspects:
                await cl.Message(f"🚨 Port scanning behavior detected from {len(port_scan_suspects)} IPs.").send()
            else:
                await cl.Message("✅ No port scan activity detected.").send()

            await cl.Message("Running suspicious HTTP method detection...").send()
            http_suspects = detect_suspicious_http_methods(entries=access_entries) if access_entries else []
            if http_suspects:
                await cl.Message(f"🚨 Suspicious HTTP methods detected in {len(http_suspects)} requests.").send()
            else:
                await cl.Message("✅ No suspicious HTTP methods found.").send()

            await cl.Message("Running DoS detection...").send()
            dos_suspects = detect_dos_attempts(access_entries) if access_entries else []
            if dos_suspects:
                await cl.Message(f"🚨 DoS attack patterns detected from {len(dos_suspects)} IPs.").send()
            else:
                await cl.Message("✅ No DoS activity detected.").send()

        combined_results = []

        if auth_suspects:
            for ip, count in auth_suspects:
                combined_results.append({"type": "brute_force", "ip": ip, "count": count})

        if access_suspects:
            for ip, reason, path in access_suspects:
                combined_results.append({"type": "web_attack", "ip": ip, "reason": reason, "path": path})

        if intrusion_suspects:
            for ip, attempts, window in intrusion_suspects:
                combined_results.append({"type": "intrusion", "ip": ip, "attempts": attempts, "window_minutes": window})

        if user_enum_suspects:
            for ip, usernames in user_enum_suspects:
                combined_results.append({"type": "user_enumeration", "ip": ip, "usernames": usernames})

        if port_scan_suspects:
            for ip, ports in port_scan_suspects:
                combined_results.append({"type": "port_scan", "ip": ip, "ports": ports})

        if http_suspects:
            for ip, method, path in http_suspects:
                combined_results.append({"type": "suspicious_http", "ip": ip, "method": method, "path": path})

        if dos_suspects:
            for ip, count in dos_suspects:
                combined_results.append({"type": "dos_attack", "ip": ip, "requests": count})

        if not combined_results:
            await cl.Message("✅ No suspicious activity found in the uploaded logs.").send()
            return

        await cl.Message("📝 Summarizing findings using AI...").send()

        documents = [Document(page_content=str(entry)) for entry in combined_results]
        splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=100)
        
        docs = splitter.split_documents(documents)

        cl.user_session.set("parsed_docs", docs)

        summary = chain.invoke({
            "context": docs,
            "question": "Summarize all suspicious activity and patterns in the logs."
        })
        await cl.Message(content=f"**Security Findings Summary**\n\n{summary}").send()
        return

    # Any other message (e.g. business context or question)
    docs = cl.user_session.get("parsed_docs")

    if not docs:
        # Store user input as business context if it's not already set
        if not cl.user_session.get("business_context"):
            cl.user_session.set("business_context", message.content.strip())
            await cl.Message("📌 Got your business context! You can now upload logs by typing 'upload logs'.").send()
        else:
            await cl.Message("⚠️ No parsed data available yet. Type 'upload logs' to begin.").send()
        return

    # Build prompt with optional business context
    business_context = cl.user_session.get("business_context", "")
    question = f"{message.content}\n\nBusiness context: {business_context}" if business_context else message.content

    response = chain.invoke({
        "context": docs,
        "question": question
    })
    await cl.Message(content=response).send()
