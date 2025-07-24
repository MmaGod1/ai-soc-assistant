from analyzer import extract_sessions
from prompt_engine import build_prompt, ask_ai
import streamlit as st

st.set_page_config(page_title="AI SOC Assistant", layout="centered")
st.title("🔐 AI SOC Assistant - PCAP Threat Analyzer")

uploaded_file = st.file_uploader("Upload a PCAP file", type=["pcap", "pcapng"])

if uploaded_file:
    with st.spinner("Analyzing file..."):
        sessions = extract_sessions(uploaded_file)
        print(f"[DEBUG] Number of extracted sessions: {len(sessions)}")

        if not sessions:
            st.error("No sessions extracted. Try another PCAP file.")
        else:
            prompt = build_prompt(sessions)
            response = ask_ai(prompt)
            st.success("Analysis complete!")
            st.markdown(response)
