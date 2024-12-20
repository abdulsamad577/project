import requests
import streamlit as st
from transformers import pipeline

def main():
    # Set up the Streamlit page configuration
    st.set_page_config(
        page_title="Vulnerability Chatbot",
        page_icon="🛡️",
        layout="wide",
    )

    # Sidebar for navigation and information
    with st.sidebar:
        st.title("Vulnerability Chatbot")
        st.markdown("""
        - **Analyze CVE IDs or vulnerability details**  
        - **Fetch data directly from NVD API**  
        - **Generate actionable remediation suggestions**
        """)
        st.info("Ensure your CVE ID or input is accurate for best results.")

    # Main title
    st.title("🛡️ Vulnerability Chatbot")

    # Input section
    st.header("🔍 Analyze a Vulnerability")
    user_input = st.text_input(
        "Enter CVE ID:",
        placeholder="e.g., CVE-2021-44228 (Log4Shell)"
    )

    # Analyze button
    if st.button("Analyze Vulnerability"):
        if user_input.strip():
            # Fetch vulnerability data
            with st.spinner("Fetching vulnerability details..."):
                vulnerability_details = fetch_vulnerability_data(user_input)

            if vulnerability_details:
                # Display vulnerability details
                st.success("Vulnerability details retrieved successfully!")
                st.subheader("📝 Vulnerability Details:")
                for key, value in vulnerability_details.items():
                    st.write(f"**{key}:** {value}")

                # Generate fix suggestions
                with st.spinner("Generating fix suggestions..."):
                    suggestions = generate_fix_suggestions(vulnerability_details)

                st.subheader("💡 Fix Suggestions:")
                st.write(suggestions)
            else:
                st.error("No details found for the provided input.")
        else:
            st.warning("Please enter a valid CVE ID or vulnerability details.")

# Function to fetch vulnerability data from NVD API
def fetch_vulnerability_data(cve_id):
    try:
        url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
        headers = {"apiKey": "e163cd63-1c76-47e6-98d7-f27fa7a5bb4d"}
        response = requests.get(url, headers=headers)
        data = response.json()

        if response.status_code == 200:
            if 'vulnerabilities' in data and len(data['vulnerabilities']) > 0:
                cve_data = data['vulnerabilities'][0]
                metrics = cve_data.get('metrics', {})

                cvss_v31 = metrics.get('cvssMetricV31', [{}])[0].get('cvssData', {})
                severity = cvss_v31.get('baseSeverity', 'Not Available')
                cvss_score = cvss_v31.get('baseScore', 'Not Available')

                return {
                    "CVE ID": cve_data.get('cve', {}).get('id', 'Not Available'),
                    "Description": cve_data.get('cve', {}).get('descriptions', [{}])[0].get('value', 'No description available').strip(),
                    "Severity": severity,
                    "CVSS Score": cvss_score,
                }
        return None
    except Exception as e:
        st.error(f"Error fetching data: {e}")
        return None

# Function to generate fix suggestions using Hugging Face Model
def generate_fix_suggestions(vulnerability_details):
    try:
        generator = pipeline("text-generation", model="gpt2")
        prompt = (
            f"Provide actionable remediation suggestions for the following vulnerability details:\n"
            f"CVE ID: {vulnerability_details.get('CVE ID', 'N/A')}\n"
            f"Description: {vulnerability_details.get('Description', 'N/A')}\n"
            f"Severity: {vulnerability_details.get('Severity', 'N/A')}\n"
            f"CVSS Score: {vulnerability_details.get('CVSS Score', 'N/A')}"
        )
        suggestions = generator(prompt, max_length=150, num_return_sequences=1)[0]['generated_text']
        return suggestions.strip()
    except Exception as e:
        st.error(f"Error generating suggestions: {e}")
        return "Could not generate suggestions."

if __name__ == "__main__":
    main()
