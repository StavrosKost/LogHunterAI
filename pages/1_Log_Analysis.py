import streamlit as st
import pandas as pd
import os
from dotenv import load_dotenv
import plotly.express as px # Import Plotly
import datetime # Needed for potential usage tracking later
import io

# Helper function for CSV conversion
@st.cache_data # Cache the conversion to prevent re-computation
def convert_df_to_csv(df):
    # IMPORTANT: Cache the conversion to prevent computation on every rerun
    return df.to_csv(index=False).encode('utf-8')

# Cache unique value extraction for filters
@st.cache_data
def get_unique_filter_values(series):
    if series is None or series.empty:
        return []
    return sorted(series.dropna().unique())

# Cache Plotly figure generation
@st.cache_data
def generate_anomaly_timeline(anomaly_df):
    if 'timestamp' not in anomaly_df.columns or not pd.api.types.is_datetime64_any_dtype(anomaly_df['timestamp']):
        return None # Cannot generate plot

    try:
        # Ensure timestamp is timezone-naive or consistent for plotting
        time_col = anomaly_df['timestamp']
        if time_col.dt.tz is not None:
            time_data = time_col.dt.tz_convert(None) # Convert to naive
        else:
            time_data = time_col

        # Count anomalies per time unit (e.g., per minute)
        anomaly_counts = time_data.dt.floor('T').value_counts().sort_index().reset_index()
        if not anomaly_counts.empty:
            anomaly_counts.columns = ['Timestamp', 'Anomaly Count']
            fig = px.bar(anomaly_counts, x='Timestamp', y='Anomaly Count', title='Anomaly Frequency Over Time')
            fig.update_layout(xaxis_title='Time', yaxis_title='Number of Anomalies')
            return fig
        else:
            return None # No data to plot
    except Exception as e:
        st.warning(f"Could not generate anomaly timeline figure: {e}") # Log warning
        return None

# Cache Log Level Pie Chart generation
@st.cache_data
def generate_log_level_pie(df):
    if 'log_level' not in df.columns or df['log_level'].isnull().all():
        return None # Cannot generate plot if column missing or all null
    try:
        level_counts = df['log_level'].value_counts().reset_index()
        level_counts.columns = ['Log Level', 'Count']
        if not level_counts.empty:
            fig = px.pie(level_counts, names='Log Level', values='Count', title='Log Level Distribution',
                         color_discrete_sequence=px.colors.qualitative.Pastel)
            fig.update_traces(textposition='inside', textinfo='percent+label')
            return fig
        else:
            return None
    except Exception as e:
        st.warning(f"Could not generate log level pie chart: {e}")
        return None

# Cache Top Anomalous IPs Chart
@st.cache_data
def generate_top_anomalous_ips_chart(anomaly_df, top_n=10):
    if 'source_ip' not in anomaly_df.columns or anomaly_df['source_ip'].isnull().all():
        return None
    try:
        top_ips = anomaly_df['source_ip'].value_counts().nlargest(top_n).reset_index()
        top_ips.columns = ['Source IP', 'Anomaly Count']
        if not top_ips.empty:
            fig = px.bar(top_ips, x='Source IP', y='Anomaly Count', title=f'Top {top_n} Anomalous Source IPs',
                         color_discrete_sequence=px.colors.qualitative.Bold)
            fig.update_layout(xaxis_title='Source IP Address', yaxis_title='Number of Anomalies')
            return fig
        else:
            return None
    except Exception as e:
        st.warning(f"Could not generate top IPs chart: {e}")
        return None

# Cache Top Anomalous Users Chart
@st.cache_data
def generate_top_anomalous_users_chart(anomaly_df, top_n=10):
    if 'user_id' not in anomaly_df.columns or anomaly_df['user_id'].isnull().all():
        return None
    try:
        top_users = anomaly_df['user_id'].value_counts().nlargest(top_n).reset_index()
        top_users.columns = ['User ID', 'Anomaly Count']
        if not top_users.empty:
            fig = px.bar(top_users, x='User ID', y='Anomaly Count', title=f'Top {top_n} Anomalous User IDs',
                         color_discrete_sequence=px.colors.qualitative.Antique)
            fig.update_layout(xaxis_title='User Identifier', yaxis_title='Number of Anomalies')
            return fig
        else:
            return None
    except Exception as e:
        st.warning(f"Could not generate top users chart: {e}")
        return None

# --- End Caching Helper Functions --- #

# Import local modules
from log_processor import load_and_parse_log_file
from anomaly_detector import preprocess_for_anomaly, detect_anomalies_isoforest, ALL_FEATURE_TYPES
# Import all summarizer functions
from summarizer import (summarize_logs_openai, explain_anomaly_openai,
                        summarize_logs_ollama, explain_anomaly_ollama)

# Load environment variables (for potential API keys)
# Place your .env file in the same directory as app.py or a parent directory
load_dotenv()

# --- Constants ---
# MAX_DISPLAY_LINES = 1000 # No longer needed for raw display
LOG_SAMPLE_FOR_SUMMARY = 50 # Number of lines to send for summarization
ANOMALY_PAGE_SIZE = 50 # Number of anomalies to show per page
RAW_PAGE_SIZE = 500 # Number of raw logs to show per page

# --- Tier Definitions & Limits ---
TIER_LIMITS = {
    "Free": {"gpt_calls": 0, "log_lines": 1000},
    "Pro": {"gpt_calls": 50, "log_lines": 10000},
    "Team": {"gpt_calls": 500, "log_lines": 100000},
    # Add Enterprise later if needed
}

# --- Streamlit App Configuration ---
# Page config is now set in each page individually
st.title("🛡️ Log Analysis Tool") # Changed title slightly

# Remove comments for Session State
# --- Session State Initialization ---
# Use .get() for safer access and default values
# These should ideally be initialized in the main app or home page if needed globally,
# but for now, we keep them here for the analysis page to function independently.
if 'log_df' not in st.session_state: # This will hold the potentially *truncated* data for analysis
    st.session_state.log_df = pd.DataFrame()
if 'original_log_df' not in st.session_state: # This will hold the full, untruncated data
    st.session_state.original_log_df = pd.DataFrame()
if 'analysis_done' not in st.session_state:
    st.session_state.analysis_done = False
if 'summary' not in st.session_state:
    st.session_state.summary = ""
if 'uploaded_file_name' not in st.session_state:
    st.session_state.uploaded_file_name = None
if 'selected_features' not in st.session_state:
    st.session_state.selected_features = ALL_FEATURE_TYPES
if 'anomaly_rate' not in st.session_state:
    st.session_state.anomaly_rate = 10
if 'results_df' not in st.session_state:
    st.session_state.results_df = pd.DataFrame()
if 'results_features' not in st.session_state:
    st.session_state.results_features = []
if 'explain_line_number' not in st.session_state:
    st.session_state.explain_line_number = None
if 'explanation_text' not in st.session_state:
    st.session_state.explanation_text = ""
if 'explanation_cache' not in st.session_state:
    st.session_state.explanation_cache = {} # Initialize cache dictionary
if 'user_tier' not in st.session_state:
    st.session_state.user_tier = "Free" # Default to Free tier
if 'gpt_usage_count' not in st.session_state:
    st.session_state.gpt_usage_count = 0
# Add session state for LLM provider selection
if 'selected_llm_provider' not in st.session_state:
    st.session_state.selected_llm_provider = "OpenAI" # Default to OpenAI
# Add session state for Ollama model selection if needed later
# if 'ollama_model' not in st.session_state:
#    st.session_state.ollama_model = "llama2"

if 'current_page' not in st.session_state: # For anomaly pagination
    st.session_state.current_page = 1
if 'raw_current_page' not in st.session_state: # For raw data pagination
    st.session_state.raw_current_page = 1

# --- Callback Functions --- #
def reset_analysis_state():
    """Clears all data related to the current log file and analysis."""
    keys_to_reset = [
        'log_df', 'original_log_df', 'uploaded_file_name', 'uploaded_file_content',
        'analysis_done', 'summary', 'results_df', 'results_features',
        'explain_line_number', 'explanation_text', 'explanation_cache',
        'gpt_usage_count', 'current_page', 'raw_current_page'
        # Do NOT reset: 'user_tier', 'selected_llm_provider' (user preferences)
    ]
    for key in keys_to_reset:
        if key in st.session_state:
            if isinstance(st.session_state[key], pd.DataFrame):
                st.session_state[key] = pd.DataFrame() # Reset DataFrame correctly
            elif isinstance(st.session_state[key], list):
                 st.session_state[key] = []
            elif isinstance(st.session_state[key], dict):
                 st.session_state[key] = {}
            elif isinstance(st.session_state[key], bool):
                 st.session_state[key] = False
            elif isinstance(st.session_state[key], (int, float)):
                 st.session_state[key] = 0 # Reset counters, handle page number later
            else:
                 st.session_state[key] = None # Default reset
    # Special handling
    st.session_state.current_page = 1 # Reset anomaly page to 1
    st.session_state.raw_current_page = 1 # Reset raw page to 1
    st.session_state.summary = "" # Ensure summary is empty string
    st.session_state.explanation_text = "" # Ensure explanation is empty string
    # We might need to reset the file uploader visually, though state clearing is main goal
    # st.session_state.file_uploader = None # This might not work as expected
    st.toast("Analysis state cleared.", icon="🧹")

def tier_change():
    st.session_state.gpt_usage_count = 0 # Reset GPT counter
    new_tier = st.session_state.tier_simulation_selectbox # Get the newly selected tier
    new_limit = TIER_LIMITS[new_tier]['log_lines']
    data_changed = False
    
    # Check if file content exists in session state
    uploaded_file_bytes = st.session_state.get('uploaded_file_content')
    
    if uploaded_file_bytes:
        with st.spinner(f"Reloading data for {new_tier} tier (limit: {new_limit} lines)..."):
            current_len = len(st.session_state.log_df) if 'log_df' in st.session_state else 0
            
            # Create a NEW BytesIO object from stored bytes for reloading
            bytes_io_for_reload = io.BytesIO(uploaded_file_bytes)
            new_log_data = load_and_parse_log_file(bytes_io_for_reload, max_lines=new_limit)
            new_len = len(new_log_data)
            
            # Check if the length actually changed
            if new_len != current_len:
                st.session_state.log_df = new_log_data
                data_changed = True
                if new_len < current_len:
                    st.toast(f"Log data truncated to {new_len} lines for {new_tier} tier.", icon="✂️")
                else:
                    st.toast(f"Now using {new_len} lines for {new_tier} tier.", icon="✅")
            else:
                 data_changed = False # Lengths match, no effective change
                 
    else:
        # No file loaded, do nothing
        pass 

    # --- Clear analysis results if data changed --- #
    if data_changed:
        st.session_state.analysis_done = False
        st.session_state.results_df = pd.DataFrame()
        st.session_state.results_features = []
        st.session_state.explanation_cache = {}
        st.session_state.explanation_text = ""
        st.session_state.explain_line_number = None
        st.warning("Tier change modified the number of log lines. Please re-run analysis if needed.", icon="⚠️")
        # st.rerun() # Rerun should happen naturally


selected_tier = st.sidebar.selectbox(
    "Simulate User Tier:",
    options=list(TIER_LIMITS.keys()),
    key='tier_simulation_selectbox', # Use the NEW key
    index=list(TIER_LIMITS.keys()).index(st.session_state.user_tier), # Set default based on session state
    on_change=tier_change # Restore the on_change callback
)
# Update session state if the selector changes
st.session_state.user_tier = selected_tier

# Display current usage (for simulation purposes)
st.sidebar.write(f"Tier: **{st.session_state.user_tier}**")

# Only show GPT counter and limits if OpenAI is selected
if st.session_state.selected_llm_provider == "OpenAI":
    current_limit = TIER_LIMITS[st.session_state.user_tier]['gpt_calls']
    st.sidebar.write(f"OpenAI Calls Used (Session): **{st.session_state.gpt_usage_count} / {current_limit if current_limit > 0 else 'Unlimited'}**")
    # --- Usage Warning --- #
    if current_limit > 0: # Only show warning if there is a limit
        usage_percentage = (st.session_state.gpt_usage_count / current_limit) * 100
        if 80 <= usage_percentage < 100:
            st.sidebar.warning(f"Nearing OpenAI limit ({usage_percentage:.0f}% used). Upgrade for more!", icon="⚠️")
        elif usage_percentage >= 100:
            st.sidebar.error(f"OpenAI limit reached for this session.", icon="🚨")
else:
    st.sidebar.info("Ollama usage is not tracked/limited by tiers.")

st.sidebar.divider()

# --- Sidebar Upload & Configure (Moved Earlier) --- #
st.sidebar.header("Upload & Configure")
uploaded_file = st.sidebar.file_uploader(
    "Upload Log File (.log, .txt)",
    type=["log", "txt"],
    key="file_uploader", # Add key to help manage state
    on_change=None # We handle the change logic below
)
st.sidebar.button("🧹 Clear Analysis State", on_click=reset_analysis_state, help="Clear uploaded file data and all analysis results.")

# --- Anomaly Detection Sidebar Options (Moved Earlier) --- #
st.sidebar.subheader("Anomaly Detection Options")
anomaly_rate = st.sidebar.slider(
    "Expected Anomaly Rate (%)",
    min_value=1,
    max_value=50,
    value=st.session_state.get('anomaly_rate', 10), # Get from session state
    step=1,
    help="Estimate the percentage of anomalies expected in the data (Isolation Forest). Higher values detect more points as anomalies.",
    key="anomaly_slider", # Add key
    disabled=st.session_state.log_df.empty # Disable if no file loaded
)
st.session_state.anomaly_rate = anomaly_rate # Store selection

selected_features = st.sidebar.multiselect(
    'Select Features for Detection:',
    options=ALL_FEATURE_TYPES, # This now includes the new types
    default=st.session_state.get('selected_features', ALL_FEATURE_TYPES), # Default to all or previous selection
    help="Choose which feature categories to use for anomaly detection. Includes time, level, length, presence, login status, auth method.", # Updated help text
    key="feature_select",
    disabled=st.session_state.log_df.empty # Disable if no file loaded
)
st.session_state.selected_features = selected_features # Store selection

# --- Add the Run Analysis button definition HERE --- #
run_analysis_button = st.sidebar.button(
    "Run Anomaly Detection",
    key="run_analysis_button_key", # Use a different key just in case
    disabled=st.session_state.log_df.empty # Disable if no file loaded
)
# --- End Add Button --- #

# --- LLM Provider Selection --- #
st.sidebar.subheader("AI Provider")
llm_options = ["OpenAI", "Ollama"]
selected_provider = st.sidebar.radio(
    "Choose AI model provider:",
    options=llm_options,
    key='selected_llm_provider', # Use existing session state key
    index=llm_options.index(st.session_state.selected_llm_provider), # Set default based on state
    horizontal=True, # Display options horizontally
    help="Select OpenAI (requires API key) or a local Ollama instance."
)
# Session state updates automatically due to the key
st.sidebar.caption("_(AI features may require setup/API keys)_ ")

# --- LLM Provider --- #
st.sidebar.divider()

# --- File Handling Logic (Moved Earlier) --- #
# Check if a new file has been uploaded
new_file_uploaded = False
if uploaded_file is not None and st.session_state.get('uploaded_file_name') != uploaded_file.name:
    new_file_uploaded = True
    st.session_state.uploaded_file_name = uploaded_file.name # Store the new filename immediately
    st.session_state.uploaded_file_content = uploaded_file.getvalue() # Store the content (bytes)
    # Clear old analysis state when a new file is detected
    st.session_state.log_df = pd.DataFrame()
    st.session_state.original_log_df = pd.DataFrame() # Keep this clear
    st.session_state.analysis_done = False
    st.session_state.summary = ""
    st.session_state.results_df = pd.DataFrame() # Also clear results
    st.session_state.results_features = []
    st.session_state.explanation_cache = {} # Clear explanation cache
    st.session_state.explanation_text = ""
    st.session_state.explain_line_number = None
    st.session_state.gpt_usage_count = 0 # Reset GPT count on new file upload

# Check if file was removed
file_removed = False
if st.session_state.get('uploaded_file_name') is not None and uploaded_file is None:
     file_removed = True
     st.session_state.uploaded_file_name = None # Clear filename
     st.session_state.uploaded_file_content = None # Clear content
     # Clear state when file is removed
     st.session_state.log_df = pd.DataFrame()
     st.session_state.original_log_df = pd.DataFrame() # Clear original data too
     st.session_state.analysis_done = False
     st.session_state.summary = ""
     st.session_state.results_df = pd.DataFrame()
     st.session_state.results_features = []
     st.session_state.explanation_cache = {}
     st.session_state.explanation_text = ""
     st.session_state.explain_line_number = None
     st.session_state.gpt_usage_count = 0 # Reset GPT count on file removal


# Process the uploaded file if it's new and not yet loaded
# Load only limited lines initially
if new_file_uploaded and st.session_state.log_df.empty: 
     with st.spinner("Loading and parsing log file..."):
         tier_log_limit = TIER_LIMITS[st.session_state.user_tier]['log_lines']
         file_content = st.session_state.get('uploaded_file_content') 
         if file_content:
             # Create a BytesIO object for the parsing function
             bytes_io_obj = io.BytesIO(file_content)
             log_data = load_and_parse_log_file(bytes_io_obj, max_lines=tier_log_limit) 
             
             if log_data.empty: # No need to check file_to_load, check log_data directly
                 st.session_state.uploaded_file_name = None # Reset if loading failed
                 st.session_state.uploaded_file_content = None 
                 st.session_state.log_df = pd.DataFrame()
             elif not log_data.empty:
                 st.session_state.log_df = log_data 
                 # Success message is now inside load_and_parse_log_file
             else: 
                 st.session_state.log_df = pd.DataFrame()
         else: # Should not happen if new_file_uploaded is True, but safety check
             st.error("Internal error: Could not access uploaded file content.")
             st.session_state.log_df = pd.DataFrame()

     # Rerun should happen naturally due to state change
     # st.rerun() 

# If file was just removed, rerun to clear the UI
if file_removed:
    st.info("File removed. Upload a new log file.") # Show message after rerun clears UI
    # st.rerun() # Remove this - state changes should trigger necessary reruns


# --- Automation & Alerts Placeholders ---
st.sidebar.subheader("Automation & Alerts")

# 1. Scheduled Jobs (Pro+)
schedule_disabled = (st.session_state.user_tier == "Free")
schedule_help = "Daily scheduled analysis requires Pro tier or higher." if schedule_disabled else "Enable automatic daily log analysis (functionality not implemented)."
st.sidebar.checkbox("Enable Daily Scheduled Analysis", key="schedule_toggle", disabled=schedule_disabled, help=schedule_help)
if schedule_disabled:
    st.sidebar.caption("_(Requires Pro/Team)_ ")

# 2. Email Alerts (Pro+)
email_alert_disabled = (st.session_state.user_tier == "Free")
email_alert_help = "Email alerts require Pro tier or higher." if email_alert_disabled else "Configure email notifications for detected anomalies (functionality not implemented)."
st.sidebar.button("Configure Email Alerts", key="email_alert_button", disabled=email_alert_disabled, help=email_alert_help)
if email_alert_disabled:
    st.sidebar.caption("_(Requires Pro/Team)_ ")

# 3. Slack/Webhook Alerts (Team+)
webhook_alert_disabled = (st.session_state.user_tier in ["Free", "Pro"])
webhook_alert_help = "Slack/Webhook alerts require Team tier or higher." if webhook_alert_disabled else "Configure Slack or Webhook notifications (functionality not implemented)."
st.sidebar.button("Configure Slack/Webhook Alerts", key="webhook_alert_button", disabled=webhook_alert_disabled, help=webhook_alert_help)
if webhook_alert_disabled:
    st.sidebar.caption("_(Requires Team)_ ")

st.sidebar.divider()

# Remove comments for Main Content Area
# --- Main Content Area --- #
# Display content only if a file is loaded successfully
if not st.session_state.log_df.empty:
    tab1, tab2, tab3 = st.tabs(["Raw Data", "Anomaly Detection", "AI Summary"])

    # --- Tab 1: Raw Data --- #
    with tab1:
        # Get the full dataframe for this tab
        raw_df = st.session_state.log_df
        total_raw_lines = len(raw_df)
        
        # Calculate total pages for raw data
        total_raw_pages = max(1, (total_raw_lines + RAW_PAGE_SIZE - 1) // RAW_PAGE_SIZE)
        
        # Ensure current page is valid
        if st.session_state.raw_current_page < 1:
            st.session_state.raw_current_page = 1
        elif st.session_state.raw_current_page > total_raw_pages:
            st.session_state.raw_current_page = total_raw_pages
            
        # Calculate start and end indices for slicing raw data
        start_idx_raw = (st.session_state.raw_current_page - 1) * RAW_PAGE_SIZE
        end_idx_raw = start_idx_raw + RAW_PAGE_SIZE

        # Slice the DataFrame for the current raw page
        paginated_raw_logs = raw_df.iloc[start_idx_raw:end_idx_raw]

        # Update subheader with pagination info
        st.subheader(f"Parsed Log Data (Rows {start_idx_raw+1}-{min(end_idx_raw, total_raw_lines)} of {total_raw_lines})")
        
        # Define the columns we want to show by default
        display_cols_raw = [
            'line_number', 'timestamp', 'log_level', 'source_ip', 'user_id', 'message', 'raw_log'
        ]
        # Ensure columns exist in the dataframe before trying to display
        valid_display_cols = [col for col in display_cols_raw if col in paginated_raw_logs.columns]

        if valid_display_cols:
            # Display the PAGINATED raw data
            st.dataframe(
                paginated_raw_logs[valid_display_cols], # Use the paginated slice
                use_container_width=True,
                height=600,  # Keep increased height
                column_config={ # Keep column config
                    "message": st.column_config.TextColumn(width="large"),
                    "raw_log": st.column_config.TextColumn(width="large")
                }
            )
            
            # --- Pagination Controls for Raw Data (Moved Here) --- #
            raw_pg_col1, raw_pg_col2, raw_pg_col3 = st.columns([5, 2, 2]) # Adjusted width for number input visibility
            with raw_pg_col2: # Use middle column for input
                raw_page_num = st.number_input(
                    f"Page ({total_raw_pages} total pages)",
                    min_value=1,
                    max_value=total_raw_pages,
                    value=st.session_state.raw_current_page,
                    step=1,
                    key='raw_page_number', # Unique key for raw page input
                    label_visibility="collapsed"
                )
                # Update session state if number input changes
                if raw_page_num != st.session_state.raw_current_page:
                     st.session_state.raw_current_page = raw_page_num
                     st.rerun() # Rerun needed to display the new page

            with raw_pg_col3: # Use rightmost column for text
                st.write(f"Page {st.session_state.raw_current_page} of {total_raw_pages}")
                
        else:
            st.warning("Log DataFrame seems to be missing expected columns or is empty.")

    # --- Tab 2: Anomaly Detection --- #
    with tab2:
        st.header("Detected Anomalies & Analysis")
        run_analysis_button= True
        # --- Execute Analysis on Button Click --- #
        if run_analysis_button:
            # Reset specific results before running, keep file data
            st.session_state.results_df = pd.DataFrame()
            st.session_state.results_features = []
            st.session_state.explanation_cache = {} # Clear cache on new run
            st.session_state.explanation_text = ""
            st.session_state.explain_line_number = None
            st.session_state.analysis_done = False # Reset flag

            with st.spinner('Analyzing logs for anomalies...'):
                if not st.session_state.log_df.empty and 'raw_log' in st.session_state.log_df.columns:
                    # Always work on a copy
                    df_copy = st.session_state.log_df.copy()
                    
                    # Use the selected features from session state
                    features_df, scaled_features, scaler = preprocess_for_anomaly(df_copy, st.session_state.selected_features)
                    
                    if scaled_features is not None and scaled_features.shape[0] > 0:
                        # Get the contamination rate from the slider and convert to proportion
                        contamination_rate = st.session_state.anomaly_rate / 100.0
                        predictions = detect_anomalies_isoforest(scaled_features, contamination=contamination_rate)

                        if predictions is not None and len(predictions) == len(df_copy):
                            df_copy['anomaly_detected'] = (predictions == -1)
                            # Ensure feedback column exists (initialize if needed)
                            if 'feedback' not in df_copy.columns:
                                df_copy['feedback'] = 'Unreviewed' # Initialize with default
                            else:
                                # Ensure existing values are valid or default
                                valid_feedback = ["Unreviewed", "True Positive", "False Positive"]
                                df_copy['feedback'] = df_copy['feedback'].astype(str).fillna('Unreviewed')
                                df_copy['feedback'] = df_copy['feedback'].apply(lambda x: x if x in valid_feedback else 'Unreviewed')

                            # Store results and used features in session state
                            st.session_state.results_df = df_copy
                            st.session_state.results_features = list(st.session_state.selected_features) # Store the features used as list
                            st.session_state.analysis_done = True
                            st.success('Anomaly detection complete!') # Show success message
                        else:
                            st.error(f"Prediction count ({len(predictions) if predictions is not None else 'None'}) does not match log line count ({len(df_copy)}). Cannot assign results.")
                    else:
                        # Error messages should be handled within preprocess_for_anomaly
                        st.warning("Could not extract or scale features. Check log format and selected features.")
                elif st.session_state.log_df.empty:
                    st.warning("Please upload a log file first.") # Should not happen if button is disabled
                else:
                     st.error("Column 'raw_log' not found in the loaded data. Cannot run anomaly detection.")
            # Rerun should happen naturally due to state change
            # st.rerun() # Comment out

        # --- Display Results --- #
        # Check if analysis has been performed (results are in session state)
        if st.session_state.analysis_done and 'results_df' in st.session_state and not st.session_state.results_df.empty and 'results_features' in st.session_state:
            results = st.session_state.results_df
            results_features = st.session_state.results_features # Features used for this result set

            # --- Display Overall Stats / Charts --- #
            stat_cols = st.columns(2)
            with stat_cols[0]:
                 log_level_pie = generate_log_level_pie(results)
                 if log_level_pie:
                     st.plotly_chart(log_level_pie, use_container_width=True, key="log_level_pie_chart") # Added key
                 else:
                     st.caption("Log Level data not available for chart.")
            # Add other chart column here later (e.g., top IPs)
            with stat_cols[1]:
                st.metric("Total Lines Processed", len(results))
                st.metric("Anomalies Detected", len(results[results['anomaly_detected'] == True]))

            st.divider()

            # Define anomalies_df immediately after getting results
            anomalies_df = results[results['anomaly_detected'] == True]

            st.success(f"Analysis complete using features: {', '.join(results_features)}")

            # Check if any anomalies were actually found
            if not anomalies_df.empty:
                st.write(f"Detected {len(anomalies_df)} potential anomalies.")

                # --- Anomaly Timeline --- #
                st.subheader("Anomaly Timeline")
                timeline_fig = generate_anomaly_timeline(anomalies_df)
                if timeline_fig:
                    st.plotly_chart(timeline_fig, use_container_width=True)
                else:
                    st.info("Timestamps not available or not in a recognizable format for timeline visualization.")

                # --- Top Anomalous Entities --- #
                st.subheader("Top Anomalous Entities")
                chart_cols = st.columns(2)
                with chart_cols[0]:
                    top_ips_chart = generate_top_anomalous_ips_chart(anomalies_df)
                    if top_ips_chart:
                        st.plotly_chart(top_ips_chart, use_container_width=True)
                    else:
                         st.caption("Source IP data not available for chart.")
                with chart_cols[1]:
                     top_users_chart = generate_top_anomalous_users_chart(anomalies_df)
                     if top_users_chart:
                         st.plotly_chart(top_users_chart, use_container_width=True)
                     else:
                         st.caption("User ID data not available for chart.")

                st.divider() # Add divider before filters

                # --- Filtering and Feedback Section --- #
                st.subheader("Filter & Review Anomalies")

                # --- Filter Widgets Row 1: Log Level, IP, User --- #
                filter_cols = st.columns(3)
                selected_levels = []
                selected_ips = []
                selected_users = []
                col_idx = 0

                # Conditionally display filters based on features used in the run
                # Check for 'log_level' feature type
                if 'log_level' in results_features and 'log_level' in results.columns:
                    with filter_cols[col_idx]:
                        # Use cached function for options
                        unique_levels = get_unique_filter_values(results['log_level'])
                        if unique_levels:
                           selected_levels = st.multiselect('Filter by Log Level:', options=unique_levels, default=[], key='filter_level')
                        else:
                           st.caption("No unique log levels found.")
                    col_idx = (col_idx + 1) % 3

                # Check for 'ip_presence' feature type to show 'source_ip' filter
                if 'ip_presence' in results_features and 'source_ip' in results.columns:
                    with filter_cols[col_idx]:
                        # Use cached function for options
                        unique_ips = get_unique_filter_values(results['source_ip'])
                        if unique_ips:
                            selected_ips = st.multiselect('Filter by Source IP:', options=unique_ips, default=[], key='filter_ip')
                        else:
                            st.caption("No unique source IPs found.")
                    col_idx = (col_idx + 1) % 3

                # Check for 'user_presence' feature type to show 'user_id' filter
                if 'user_presence' in results_features and 'user_id' in results.columns:
                     with filter_cols[col_idx]:
                        # Use cached function for options
                        unique_users = get_unique_filter_values(results['user_id'])
                        if unique_users:
                            selected_users = st.multiselect('Filter by User ID:', options=unique_users, default=[], key='filter_user')
                        else:
                             st.caption("No unique User IDs found.")
                     col_idx = (col_idx + 1) % 3

                # --- Filter Widgets Row 2: Date Range --- #
                date_filter_cols = st.columns([1, 1, 2]) # Date inputs + Spacer
                start_date = None
                end_date = None
                # Check if timestamp column is suitable for date filtering
                if 'timestamp' in results.columns and pd.api.types.is_datetime64_any_dtype(results['timestamp']):
                    min_date = results['timestamp'].min().date() if not results['timestamp'].isnull().all() else datetime.date.today()
                    max_date = results['timestamp'].max().date() if not results['timestamp'].isnull().all() else datetime.date.today()

                    with date_filter_cols[0]:
                        start_date = st.date_input("Start Date", value=None, min_value=min_date, max_value=max_date, key="filter_start_date")
                    with date_filter_cols[1]:
                        end_date = st.date_input("End Date", value=None, min_value=min_date, max_value=max_date, key="filter_end_date")
                else:
                    with date_filter_cols[0]:
                         st.caption("Timestamp data unavailable for date filtering.")

                # --- Apply Filters --- #
                filtered_anomalies = anomalies_df.copy()
                # Apply existing filters
                try:
                    if selected_levels and 'log_level' in filtered_anomalies.columns:
                        filtered_anomalies = filtered_anomalies[filtered_anomalies['log_level'].isin(selected_levels)]
                    if selected_ips and 'source_ip' in filtered_anomalies.columns:
                        filtered_anomalies = filtered_anomalies[filtered_anomalies['source_ip'].isin(selected_ips)]
                    if selected_users and 'user_id' in filtered_anomalies.columns:
                        filtered_anomalies = filtered_anomalies[filtered_anomalies['user_id'].isin(selected_users)]

                    # Apply Date Filter (if dates are valid and column exists)
                    if start_date and end_date and start_date > end_date:
                        st.warning("Start date cannot be after end date.")
                    elif 'timestamp' in filtered_anomalies.columns and pd.api.types.is_datetime64_any_dtype(filtered_anomalies['timestamp']):
                        # Convert filter dates to datetime start/end of day for comparison
                        datetime_start = pd.to_datetime(start_date) if start_date else None
                        # Add one day and subtract a tiny delta for inclusive end date
                        datetime_end = pd.to_datetime(end_date) + pd.Timedelta(days=1) - pd.Timedelta(seconds=1) if end_date else None

                        if datetime_start:
                            filtered_anomalies = filtered_anomalies[filtered_anomalies['timestamp'] >= datetime_start]
                        if datetime_end:
                            filtered_anomalies = filtered_anomalies[filtered_anomalies['timestamp'] <= datetime_end]

                except Exception as e:
                     st.error(f"Error applying filters: {e}")

                # --- Display Anomaly Table (with Pagination) --- #
                total_anomalies = len(filtered_anomalies)

                if not filtered_anomalies.empty:
                    total_pages = max(1, (total_anomalies + ANOMALY_PAGE_SIZE - 1) // ANOMALY_PAGE_SIZE)

                    # Ensure current page is valid
                    if st.session_state.current_page < 1:
                        st.session_state.current_page = 1
                    elif st.session_state.current_page > total_pages:
                        st.session_state.current_page = total_pages

                    # --- Pagination Controls --- #
                    pg_col1, pg_col2, pg_col3 = st.columns([2, 1, 2])
                    with pg_col1:
                        # Use number input for page selection
                        page_num = st.number_input(
                            f"Page ({total_pages} total pages)",
                            min_value=1,
                            max_value=total_pages,
                            value=st.session_state.current_page,
                            step=1,
                            key='anomaly_page_number',
                            label_visibility="collapsed"
                        )
                        # Update session state if number input changes
                        if page_num != st.session_state.current_page:
                             st.session_state.current_page = page_num
                             st.rerun() # Rerun needed to display the new page

                    with pg_col3:
                        st.write(f"Page {st.session_state.current_page} of {total_pages}")

                    # Calculate start and end indices for slicing
                    start_idx = (st.session_state.current_page - 1) * ANOMALY_PAGE_SIZE
                    end_idx = start_idx + ANOMALY_PAGE_SIZE

                    # Slice the DataFrame for the current page
                    paginated_anomalies = filtered_anomalies.iloc[start_idx:end_idx]

                    # Update subheader with pagination info
                    st.subheader(f"Anomalies Detected (Rows {start_idx+1}-{min(end_idx, total_anomalies)} of {total_anomalies} matching filters)")

                    # Add feedback column if it doesn't exist
                    if 'feedback' not in paginated_anomalies.columns:
                         # This shouldn't happen if initialized earlier, but safe fallback
                         paginated_anomalies['feedback'] = 'Unreviewed'
                    else:
                         paginated_anomalies['feedback'] = paginated_anomalies['feedback'].astype(str).fillna('Unreviewed')

                    # Define feedback options
                    feedback_options = ["Unreviewed", "True Positive", "False Positive"]

                    # Prepare columns for display in data editor
                    display_cols_anomalies = [
                        'line_number', 'timestamp', 'log_level', 'source_ip',
                        'user_id', 'message', 'feedback'
                    ]
                    # Use only columns that actually exist in the filtered DataFrame
                    valid_display_cols_anomalies = [col for col in display_cols_anomalies if col in paginated_anomalies.columns]

                    # Display the data editor with paginated data
                    edited_df = st.data_editor(
                        paginated_anomalies[valid_display_cols_anomalies],
                        key='anomaly_feedback_editor',
                        num_rows="fixed", # Use fixed or limited to avoid excessive rendering
                        height= (ANOMALY_PAGE_SIZE + 1) * 35 + 3, # Adjust height based on page size
                        use_container_width=True,
                        column_config={
                            "feedback": st.column_config.SelectboxColumn(
                                "Feedback Status",
                                help="Classify the detected anomaly",
                                width="medium",
                                options=feedback_options,
                                required=True, # Ensure a value is always selected
                            )
                        }
                    )

                    # --- Merge Feedback back to main results_df --- # 
                    if edited_df is not None:
                        # Create a dictionary mapping line_number to feedback from the edited page
                        feedback_updates = edited_df.set_index('line_number')['feedback'].to_dict()

                        # Update the main results dataframe in session state
                        results_df = st.session_state.results_df
                        # Ensure the index is set for efficient lookup
                        if 'line_number' in results_df.columns:
                            results_df.set_index('line_number', inplace=True)
                            # Apply updates
                            for line_num, feedback in feedback_updates.items():
                                if line_num in results_df.index:
                                    results_df.loc[line_num, 'feedback'] = feedback
                            # Reset index to keep line_number as a column
                            results_df.reset_index(inplace=True)
                            st.session_state.results_df = results_df
                            # st.toast("Feedback updated.", icon="📝") # Optional: feedback on update
                        else:
                            st.warning("Could not update feedback - 'line_number' column missing.")

                    # --- AI Explanation Section --- # 
                    st.divider()
                    st.subheader("🤖 Explain Anomaly with AI")
                    # Determine which explanation function to use
                    if st.session_state.selected_llm_provider == "OpenAI":
                        explain_function = explain_anomaly_openai
                        provider_name = "OpenAI"
                        api_key = os.getenv("OPENAI_API_KEY")
                        is_configured = bool(api_key)
                        config_warning = "OpenAI API key not configured. Cannot provide AI explanations."
                    else: # Ollama
                        explain_function = explain_anomaly_ollama
                        provider_name = "Ollama"
                        is_configured = True # Assume configured if selected, error handled in function
                        config_warning = "Ollama connection failed. Ensure Ollama is running."

                    if is_configured:
                            anomaly_line_numbers = anomalies_df['line_number'].sort_values().tolist()

                            # --- Limit checks (only for OpenAI) --- #
                            can_explain = True
                            limit_message_explain = ""
                            explain_button_disabled = False # Start enabled unless check fails

                            if provider_name == "OpenAI":
                                current_tier_limit_explain = TIER_LIMITS[st.session_state.user_tier]['gpt_calls']
                                can_explain = current_tier_limit_explain > 0 and st.session_state.gpt_usage_count < current_tier_limit_explain
                                if not can_explain:
                                    explain_button_disabled = True
                                    if current_tier_limit_explain == 0:
                                        limit_message_explain = f"AI Explanations not available for **{st.session_state.user_tier}** tier with OpenAI."
                                    else:
                                        limit_message_explain = f"OpenAI Explanation limit ({current_tier_limit_explain}) reached for **{st.session_state.user_tier}** tier. Upgrade for more explanations."
                            # --- End Limit Checks --- #

                            if limit_message_explain:
                                st.warning(limit_message_explain, icon="⚠️")

                            # Further disable button if no anomalies or already disabled by limits
                            explain_button_disabled = explain_button_disabled or not anomaly_line_numbers

                            col1, col2 = st.columns([3, 1])
                            with col1:
                                selected_line = st.selectbox(
                                    f"Select anomaly line number to explain (using {provider_name}):",
                                    options=anomaly_line_numbers,
                                    index=None,
                                    key='explain_select',
                                    help="Choose an anomaly line from the detected list.",
                                    disabled=explain_button_disabled
                                )
                                if selected_line is not None:
                                    st.session_state.explain_line_number = selected_line
                                else:
                                    st.session_state.explain_line_number = None

                            with col2:
                                explain_button = st.button(f"Get {provider_name} Explanation", key="explain_button", disabled=(explain_button_disabled or selected_line is None))

                            if explain_button and selected_line is not None and can_explain:
                                st.session_state.explanation_text = "" # Clear previous

                                use_cache = (provider_name == "OpenAI") # Only cache OpenAI results for now
                                cached_result = None
                                if use_cache and selected_line in st.session_state.explanation_cache:
                                     cached_result = st.session_state.explanation_cache[selected_line]

                                if cached_result:
                                    st.session_state.explanation_text = cached_result
                                    st.info(f"Retrieved cached OpenAI explanation for line {selected_line}.")
                                    # Rerun should happen naturally due to state change
                                    # st.rerun() # Comment out
                                else:
                                    # Check OpenAI limit again just before calling (if applicable)
                                    proceed_call = True
                                    if provider_name == "OpenAI":
                                        current_tier_limit_explain = TIER_LIMITS[st.session_state.user_tier]['gpt_calls']
                                        if st.session_state.gpt_usage_count >= current_tier_limit_explain and current_tier_limit_explain > 0:
                                            proceed_call = False
                                            st.warning(limit_message_explain, icon="⚠️")
                                            # Rerun should happen naturally due to state change
                                            # st.rerun() # Comment out

                                    if proceed_call:
                                        with st.spinner(f"Asking {provider_name} to explain anomaly on line {selected_line}..."):
                                            try:
                                                log_entry_to_explain = st.session_state.results_df[st.session_state.results_df['line_number'] == selected_line].iloc[0]
                                                # Call the selected function (OpenAI or Ollama)
                                                explanation = explain_function(log_entry_to_explain)
                                                st.session_state.explanation_text = explanation
                                                # Increment usage and cache only for successful OpenAI calls
                                                if provider_name == "OpenAI" and explanation and not explanation.startswith("Error:"):
                                                    if use_cache:
                                                         st.session_state.explanation_cache[selected_line] = explanation
                                                    st.session_state.gpt_usage_count += 1
                                            except IndexError:
                                                 st.error(f"Could not find log entry for line {selected_line}.")
                                                 st.session_state.explanation_text = "Error: Log entry not found."
                                            except Exception as e:
                                                 st.error(f"An error occurred while getting explanation: {e}")
                                                 st.session_state.explanation_text = f"Error: {e}"
                                        # Rerun should happen naturally due to state change
                                        # st.rerun() # Comment out

                            # Display explanation
                            if st.session_state.explanation_text and st.session_state.explain_line_number == selected_line:
                                display_provider = "OpenAI" if cached_result else provider_name
                                if st.session_state.explanation_text.startswith("Error:"):
                                    st.error(f"**{display_provider} Explanation Error for Line {selected_line}:**\n{st.session_state.explanation_text}")
                                else:
                                    st.info(f"**{display_provider} Explanation for Line {selected_line}:**\n{st.session_state.explanation_text}")
                    else:
                        st.warning(config_warning)

                else: # Case where filters result in no anomalies being shown
                    st.info("No anomalies match the current filter criteria.")

                # --- Export Buttons (Tier-dependent & Implemented) ---
                st.divider()
                # Determine if export should be disabled
                export_disabled = (st.session_state.user_tier == "Free") or filtered_anomalies.empty
                export_tooltip = "Export requires Pro tier or higher." if (st.session_state.user_tier == "Free") else (
                    "No filtered anomalies to export." if filtered_anomalies.empty else "Download filtered anomalies."
                )

                # Prepare data (only if not empty)
                csv_data = ""
                json_data = ""
                if not filtered_anomalies.empty:
                    csv_data = convert_df_to_csv(filtered_anomalies) # Use cached function
                    # Generate JSON data (records format, one JSON object per line)
                    json_data = filtered_anomalies.to_json(orient='records', lines=True).encode('utf-8')

                # --- Display Buttons --- #
                export_cols = st.columns(2)
                with export_cols[0]:
                    st.download_button(
                        label="📋 Export as CSV",
                        data=csv_data,
                        file_name=f"loghunter_anomalies_{datetime.date.today()}.csv",
                        mime='text/csv',
                        key="export_button_csv",
                        help=export_tooltip + " (CSV Format)",
                        disabled=export_disabled,
                        use_container_width=True
                    )
                with export_cols[1]:
                     st.download_button(
                        label="📄 Export as JSON",
                        data=json_data,
                        file_name=f"loghunter_anomalies_{datetime.date.today()}.jsonl", # Use .jsonl extension for line-delimited JSON
                        mime='application/jsonl+json', # More specific MIME type if possible
                        key="export_button_json",
                        help=export_tooltip + " (JSON Lines Format)",
                        disabled=export_disabled,
                        use_container_width=True
                    )

                # Show tier limitation caption if applicable
                if st.session_state.user_tier == "Free":
                    st.caption("_(CSV/JSON Export available on Pro/Team tiers)_ ")
                elif filtered_anomalies.empty and not st.session_state.user_tier == "Free":
                    st.caption("_(No anomalies matching filters to export)_ ")

            else: # Case where detection ran but no anomalies were found
                st.info("No anomalies detected in the log file with the current settings.")
                # Optionally, add a disabled export button here too
                st.divider()
                export_cols_disabled = st.columns(2)
                with export_cols_disabled[0]:
                    st.download_button(
                        label="📋 Export as CSV",
                        data="",
                        file_name="loghunter_anomalies.csv",
                        mime='text/csv',
                        key="export_button_csv_disabled",
                        help="No anomalies detected to export.",
                        disabled=True,
                        use_container_width=True
                    )
                with export_cols_disabled[1]:
                     st.download_button(
                        label="📄 Export as JSON",
                        data="",
                        file_name="loghunter_anomalies.jsonl",
                        mime='application/jsonl+json',
                        key="export_button_json_disabled",
                        help="No anomalies detected to export.",
                        disabled=True,
                        use_container_width=True
                    )

        # Cases before analysis is run or if results were cleared
        elif st.session_state.log_df.empty:
            st.warning("Please upload a log file using the sidebar to begin.")
        else: # Log uploaded, but detection not run yet
            st.info("Click 'Run Anomaly Detection' in the sidebar to analyze the log data.")

    # --- Tab 3: AI Summary --- #
    with tab3:
        st.subheader("Log Summary (AI Generated)")
        # Determine which summary function to use
        if st.session_state.selected_llm_provider == "OpenAI":
            summarize_function = summarize_logs_openai
            provider_name_summary = "OpenAI"
            api_key = os.getenv("OPENAI_API_KEY")
            is_configured_summary = bool(api_key)
            config_warning_summary = "OpenAI API key not configured. Summarization disabled."
        else: # Ollama
            summarize_function = summarize_logs_ollama
            provider_name_summary = "Ollama"
            is_configured_summary = True # Assume configured if selected
            config_warning_summary = "Ollama connection failed. Ensure Ollama is running."

        if not is_configured_summary:
            st.warning(config_warning_summary, icon="⚠️")
        else:
            # --- Button and Logic --- #
            is_free_tier = st.session_state.user_tier == "Free"
            can_summarize = False
            limit_message = ""
            summary_button_disabled = False # Start enabled unless checks fail
            button_label = f"Generate {provider_name_summary} Summary"
            show_preview_logic = False

            if provider_name_summary == "OpenAI":
                if is_free_tier:
                    # Free tier gets a preview button for OpenAI
                    button_label = "✨ Preview OpenAI Summary (Upgrade for Full)"
                    limit_message = "AI Summaries require Pro tier or higher."
                    show_preview_logic = True
                    # summary_button_disabled = False # Already default
                else: # Pro or Team tier for OpenAI
                    current_tier_limit = TIER_LIMITS[st.session_state.user_tier]['gpt_calls']
                    can_summarize = current_tier_limit > 0 and st.session_state.gpt_usage_count < current_tier_limit
                    if not can_summarize:
                        summary_button_disabled = True
                        limit_message = f"OpenAI Summary limit ({current_tier_limit}) reached for **{st.session_state.user_tier}** tier. Upgrade for more summaries."
            # No limits applied for Ollama
            elif provider_name_summary == "Ollama":
                 # Button is enabled by default
                 pass

            # Display limit message if applicable (only for OpenAI)
            if limit_message and provider_name_summary == "OpenAI":
                 if show_preview_logic:
                      st.info(limit_message, icon="💡")
                 elif not can_summarize:
                      st.warning(limit_message, icon="⚠️")

            if st.button(button_label, key="generate_summary", disabled=summary_button_disabled):
                if show_preview_logic: # OpenAI Free Tier Preview
                    st.session_state.summary = "***Blurred Preview:***\nUpgrade to Pro or Team to unlock full AI-powered summaries! This feature analyzes your log data to provide concise insights into key events and potential issues.\n(Example: Detected unusual login activity from IP x.x.x.x, potential brute-force attempt indicated by multiple failed logins...)"
                    # Rerun should happen naturally due to state change
                    # st.rerun() # Comment out
                else: # Pro/Team OpenAI OR Ollama
                    st.session_state.summary = "" # Clear previous summary
                    # Check OpenAI limits again if applicable
                    proceed_call_summary = True
                    if provider_name_summary == "OpenAI":
                         current_tier_limit = TIER_LIMITS[st.session_state.user_tier]['gpt_calls']
                         if not (current_tier_limit > 0 and st.session_state.gpt_usage_count < current_tier_limit):
                             proceed_call_summary = False
                             st.warning(limit_message, icon="⚠️") # Show limit message again
                             # Rerun should happen naturally due to state change
                             # st.rerun() # Comment out

                    if proceed_call_summary:
                        with st.spinner(f"Generating summary using {provider_name_summary}..."):
                            if 'raw_log' in st.session_state.log_df.columns:
                                log_sample_text = "\n".join(st.session_state.log_df['raw_log'].head(LOG_SAMPLE_FOR_SUMMARY).astype(str).tolist())
                                # Call the selected function
                                summary_result = summarize_function(log_sample_text)
                                st.session_state.summary = summary_result
                                # Increment usage only for successful OpenAI calls
                                if provider_name_summary == "OpenAI" and summary_result and not summary_result.startswith("Error:"):
                                    st.session_state.gpt_usage_count += 1
                            else:
                                st.session_state.summary = "Error: 'raw_log' column not found for summarization."
                            # Rerun should happen naturally due to state change
                            # st.rerun() # Comment out

            # Display the summary or preview
            current_summary = st.session_state.get('summary', "")
            if current_summary:
                if current_summary.startswith("Error:"):
                    st.error(current_summary)
                elif show_preview_logic and current_summary.startswith("***Blurred Preview:"):
                     st.markdown("**Summary Preview:**")
                     st.info(current_summary) # Show the preview message in an info box
                else: # Actual summary (OpenAI paid or Ollama)
                    display_provider_summary = "OpenAI" if provider_name_summary == "OpenAI" and not show_preview_logic else provider_name_summary
                    st.markdown(f"**{display_provider_summary} Summary:**")
                    st.text_area(" ", value=current_summary, height=200, disabled=True, label_visibility="collapsed")
            elif not show_preview_logic: # Only show initial message for non-preview cases
                 st.markdown("Click the button above to generate an AI summary based on the first {} log lines.".format(LOG_SAMPLE_FOR_SUMMARY))


else:
    # Display this message when no file is loaded initially on this page
    st.info("Welcome to the Log Analysis tool! Upload a log file using the sidebar to begin.")

# --- Footer (Optional for individual page) ---
# st.markdown("--- ")
# st.markdown("*LogHunter AI v0.3* ") 