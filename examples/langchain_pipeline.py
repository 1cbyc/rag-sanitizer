"""LangChain ingestion example."""

from langchain.text_splitter import RecursiveCharacterTextSplitter
from langchain_community.document_loaders import PyPDFLoader
from langchain_community.vectorstores import Chroma
from langchain_openai import OpenAIEmbeddings

from rag_sanitizer.integrations.langchain import RagSanitizerTransformer


docs = PyPDFLoader("untrusted_document.pdf").load()

sanitizer = RagSanitizerTransformer(on_threat="sanitize")
clean_docs = sanitizer.transform_documents(docs)

for doc in clean_docs:
    score = doc.metadata.get("rag_sanitizer_threat_score", 0)
    if score > 0:
        print(f"[!] Threat score {score:.2f} in {doc.metadata.get('source', 'unknown')}")

splitter = RecursiveCharacterTextSplitter(chunk_size=1000, chunk_overlap=200)
chunks = splitter.split_documents(clean_docs)
vectorstore = Chroma.from_documents(chunks, OpenAIEmbeddings())
print(vectorstore)
