import streamlit as st
from phishing_analyzer.analyzer import analyze_email

st.set_page_config(page_title="PhishGuard", page_icon="🛡️", layout="wide")

st.title("🛡️ PhishGuard")
st.caption("Phishing detection platform: email header, URL, content, and domain intelligence analysis")

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

raw_email = st.text_area(
    "Paste raw email content or headers here",
    value=sample,
    height=320,
)

if st.button("Analyze Email", type="primary"):
    with st.spinner("Analyzing email..."):
        result = analyze_email(raw_email)

    st.subheader("Result")
    st.metric("Risk Score", f"{result['score']}/100", result["classification"])

    col1, col2, col3, col4 = st.columns(4)
    col1.metric("Header Score", result["breakdown"]["headers"])
    col2.metric("Content Score", result["breakdown"]["content"])
    col3.metric("URL Score", result["breakdown"]["urls"])
    col4.metric("Domain Score", result["breakdown"].get("domains", 0))

    st.subheader("Email Metadata")
    st.json(result["metadata"])

    st.subheader("Detected URLs")
    if result["urls"]:
        for url in result["urls"]:
            st.code(url)
    else:
        st.write("No URLs found.")

    st.subheader("Domain Intelligence")
    if result.get("domains"):
        for domain in result["domains"]:
            with st.expander(f"Domain: {domain['domain']}"):
                st.write(f"**Registrar:** {domain.get('registrar')}")
                st.write(f"**Creation Date:** {domain.get('creation_date')}")
                st.write(f"**Domain Age:** {domain.get('age_days')} days")
                st.write(f"**Domain Risk Score:** {domain.get('risk_score')}")

                st.write("**Domain Findings:**")
                for finding in domain.get("findings", []):
                    st.write(f"- {finding}")
    else:
        st.write("No domains found for analysis.")

    st.subheader("Findings")
    for finding in result["findings"]:
        st.write(f"- {finding}")