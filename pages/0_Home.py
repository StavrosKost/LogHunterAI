import streamlit as st

st.set_page_config(layout="wide", page_title="LogHunter AI - Home")

# --- Session State for Demo --- #
if 'show_demo' not in st.session_state:
    st.session_state.show_demo = False
if 'show_full_pricing' not in st.session_state:
    st.session_state.show_full_pricing = False

def toggle_demo():
    st.session_state.show_demo = not st.session_state.show_demo

def toggle_pricing():
    st.session_state.show_full_pricing = not st.session_state.show_full_pricing

# --- Hero Section ---
st.title("Catch Threats Before They Catch You.")
st.subheader("LogHunter AI: Smart Log Correlation with AI + ML.")
st.markdown("""
Tired of drowning in logs? We help SOC teams and analysts surface anomalies
and generate GPT-powered daily summaries — in plain English.
""")
col1, col2, col3 = st.columns([1, 1, 5]) # Adjust spacing for two buttons
with col1:
    st.button("🔍 Try LogHunter AI", key="try_free_hero", help="Select 'Log Analysis' from the sidebar menu to get started.")
with col2:
    st.button("📄 See Demo Summary", key="demo_summary_hero", on_click=toggle_demo, help="Show an example log summary.")
st.divider()

# --- Demo Expander --- #
if st.session_state.show_demo:
    with st.expander("**Sample Log Summary Demo**", expanded=True):
        st.write("Here's an example of how LogHunter AI summarizes log data:")
        # Define Sample Data
        sample_log_snippet = """
        2023-10-27 08:15:32 INFO User 'admin' logged in successfully from 192.168.1.10.
        2023-10-27 08:17:01 WARNING Failed login attempt for user 'root' from 203.0.113.45.
        2023-10-27 08:17:05 WARNING Failed login attempt for user 'root' from 203.0.113.45.
        2023-10-27 08:17:09 ERROR Multiple failed login attempts detected for user 'root' from 203.0.113.45. Account locked.
        2023-10-27 08:20:11 INFO Service 'nginx' restarted successfully.
        2023-10-27 08:22:45 DEBUG User 'alice' accessed resource '/api/data'.
        """

        sample_summary = ("**Key Events:** Successful admin login from internal IP (192.168.1.10). Nginx service restart. User 'alice' accessed API data.\n"
                          "**Potential Issues:** Multiple failed login attempts for 'root' from external IP (203.0.113.45) resulted in an account lockout, indicating a potential brute-force attack.")

        st.text_area("Sample Log Snippet:", sample_log_snippet, height=150, disabled=True)
        st.markdown("**Generated AI Summary:**")
        st.info(sample_summary)
        if st.button("Close Demo", key="close_demo_button"):
             st.session_state.show_demo = False

# --- Features Section ---
st.header("Features")
feat1, feat2, feat3 = st.columns(3)
with feat1:
    st.subheader("🔍 Detect the Undetectable")
    st.markdown("Combines static rules and ML (Isolation Forest) to flag strange behavior in real-time.")
with feat2:
    st.subheader("🧠 Understand Logs at a Glance")
    st.markdown("Daily GPT summaries tell you exactly what happened, in plain English. No more grep + guesswork.")
with feat3:
    st.subheader("📈 Simple UI, Powerful Insights")
    st.markdown("Upload logs or connect Wazuh/Sysmon (integrations planned). Let LogHunter find the signal in the noise.")
st.divider()

# --- How it Works Section ---
st.header("How it Works")
how1, how2, how3 = st.columns(3)
with how1:
    st.subheader("1. Upload")
    st.markdown("Upload your log files easily through the sidebar.")
with how2:
    st.subheader("2. Analyze")
    st.markdown("Choose your detection level: ML-based anomaly detection.")
with how3:
    st.subheader("3. Get Insights")
    st.markdown("View anomalies, get AI summaries (requires setup), and understand your logs.")
st.divider()

# --- Pricing Preview Section ---
st.header("Pricing")
st.markdown("Simple, scalable pricing to fit your needs.")

# Using columns to create a table-like structure for pricing preview
p_col1, p_col2, p_col3 = st.columns(3)
with p_col1:
    st.subheader("Free")
    st.markdown("**€0**")
    st.markdown("✓ ML Anomaly Detection")
    st.markdown("✓ 1k Logs/day")
    st.markdown("❌ GPT Summaries")
with p_col2:
    st.subheader("Pro")
    st.markdown("**€19 / month**")
    st.markdown("✓ ML Anomaly Detection")
    st.markdown("✓ 10k Logs/day")
    st.markdown("✓ 50 GPT Summaries/mo")
    st.markdown("✓ Export Reports")
    st.markdown("✓ Email Alerts")
with p_col3:
    st.subheader("Team")
    st.markdown("**€79 / month**")
    st.markdown("✓ Everything in Pro")
    st.markdown("✓ 100k Logs/day")
    st.markdown("✓ 500 GPT Summaries/mo")
    st.markdown("✓ 5 Users")
    st.markdown("✓ Slack/Webhook Alerts")
    st.markdown("✓ Basic Integrations")

# Link to full pricing (conceptual)
st.button("📊 View Full Pricing & Enterprise Options", key="view_pricing", on_click=toggle_pricing)
st.divider()

# --- Detailed Pricing Expander --- #
if st.session_state.show_full_pricing:
    with st.expander("**Full Pricing Details**", expanded=True):
        # Detailed pricing table using Markdown
        st.markdown("""
| Feature                       | Free          | Pro (€19/mo)      | Team (€79/mo)       | Enterprise (Custom) |
|-------------------------------|---------------|-------------------|-------------------|-----------------------|
| **Core Engine**               |               |                   |                   |                       |
| Static Rule Engine            | ✅            | ✅                | ✅                | ✅                    |
| Anomaly Detection (ML)        | ✅            | ✅                | ✅                | ✅                    |
| **AI Features**               |               |                   |                   |                       |
| GPT Daily Summaries           | ❌            | ✅ (50/month)     | ✅ (500/month)    | ✅ (Custom)           |
| GPT Anomaly Explanations      | ❌            | ✅ (Usage based)  | ✅ (Usage based)  | ✅ (Custom)           |
| GPT Summary Customization     | ❌            | ❌                | ❌                | ✅                    |
| **Usage & Limits**          |               |                   |                   |                       |
| Log Volume                    | 1k/day        | 10k/day           | 100k/day          | Custom                |
| Users                         | 1             | 1                 | 5                 | Unlimited             |
| **Workflow & Ops**          |               |                   |                   |                       |
| Manual Log Upload             | ✅            | ✅                | ✅                | ✅                    |
| Scheduled Jobs                | ❌            | ✅ (Daily)        | ✅ (Daily)        | ✅                    |
| Export Reports (CSV/JSON)   | ❌            | ✅                | ✅                | ✅                    |
| **Alerts & Integrations**     |               |                   |                   |                       |
| Basic Email Alerts            | ❌            | ✅                | ✅                | ✅                    |
| Slack/Webhook Alerts          | ❌            | ❌                | ✅                | ✅                    |
| Log Source Integrations       | ❌            | ❌                | ✅ (Basic)        | ✅ (Custom)           |
| **Deployment & Support**    |               |                   |                   |                       |
| Deployment                    | Cloud (Shared)| Cloud (Shared)    | Cloud (Shared)    | On-prem/Private Cloud |
| API Access                    | ❌            | ❌                | ❌                | ✅                    |
| Support Level                 | Community     | Email             | Priority          | Dedicated Team        |
""")
        st.markdown("**Enterprise Plan:** Contact us for custom pricing based on your specific log volume, deployment, integration, and support needs.")
        # Add Add-on purchase info if needed
        st.markdown("**Add-ons (Pro/Team):** Need more GPT summaries? Purchase additional bundles (e.g., 100 summaries for €5).")

        if st.button("Close Pricing", key="close_pricing_button"):
             st.session_state.show_full_pricing = False
             st.rerun()
    st.divider() # Add divider after the expander if shown


# --- Integrations Banner ---
# st.header("Integrations")
# st.markdown("""
# 🔗 **Works with (Planned):**
# *   ✅ Sysmon
# *   ✅ Wazuh
# *   ✅ Elastic Logs
# *   ✅ Custom JSON/Text Logs
# """, unsafe_allow_html=True) # Using markdown for icons might require unsafe_allow_html if using emojis/html
# st.divider()

# --- Call to Action ---
st.header("Ready to hunt threats, not grep through logs?")
st.markdown("Try LogHunter AI free — no credit card needed to start analyzing.")
col_cta1, col_cta2, col_cta3 = st.columns([1, 2, 5])
with col_cta1:
    st.button("🚀 Get Started", key="get_started_cta", help="Select 'Log Analysis' from the sidebar menu to get started.")
# with col_cta2:
#     st.button("🎥 Watch 90s Demo", key="watch_demo_cta", help="Link to a demo video (functionality not implemented yet)")
st.divider()

# --- Footer ---
st.markdown("""
---
**Product:** Features • Pricing • Demo (Conceptual Links)

**Company:** About • Blog • Contact

**Legal:** Terms • Privacy

---
""", unsafe_allow_html=True)
# Add social links if desired
# st.markdown("[GitHub](link) • [LinkedIn](link) • [Twitter](link)") 