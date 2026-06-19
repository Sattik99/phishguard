import streamlit as st
from phishing_analyzer.analyzer import analyze_email

st.set_page_config(page_title="Phishing Detection Tool", page_icon="🛡️", layout="wide")
st.title("🛡️ Phishing Detection Tool")
st.caption("Portfolio MVP: email header, URL, and content risk scoring")

sample = """From: Microsoft Security <security@microsoft-alerts.example.com>
Reply-To: support@evil-login.xyz
Return-Path: bounce@evil-login.xyz
Subject: Urgent: Verify your account immediately
Authentication-Results: spf=fail dkim=none dmarc=fail

Your account will be locked within 24 hours. Click here to verify your account:
http://microsoft.verify-login.evil-login.xyz/account

Please enter your password to continue.
Attachment: invoice.zip
"""

raw_email = st.text_area("Paste raw email content or headers here", value=sample, height=320)

if st.button("Analyze Email", type="primary"):
    result = analyze_email(raw_email)

    st.subheader("Result")
    st.metric("Risk Score", f"{result['score']}/100", result["classification"])

    col1, col2, col3 = st.columns(3)
    col1.metric("Header Score", result["breakdown"]["headers"])
    col2.metric("Content Score", result["breakdown"]["content"])
    col3.metric("URL Score", result["breakdown"]["urls"])

    st.subheader("Email Metadata")
    st.json(result["metadata"])

    st.subheader("Detected URLs")
    if result["urls"]:
        for url in result["urls"]:
            st.code(url)
    else:
        st.write("No URLs found.")

    st.subheader("Findings")
    for finding in result["findings"]:
        st.write(f"- {finding}")
