import pandas as pd
import streamlit as st
import io
import re # Import regex module
import datetime # Added for getting current year

# Regex patterns - designed to be somewhat flexible but may need tuning
# Prioritize Linux format: Month Day HH:MM:SS
LINUX_TS_PATTERN = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"
# New Linux-like format: Month Day MM:SS.ms (no hour)
LINUX_MS_NO_HOUR_TS_PATTERN = r"(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}\.\d+)" # Use \d+ for variable ms digits
# Other common formats
ISO_OFFSET_PATTERN = r"(\d{4}[-/]\d{2}[-/]\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?)"
APACHE_CLF_PATTERN = r"(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2}\s+[+-]\d{4})"

# Combine, starting with Linux format. Match must be at start, followed by space.
# Use non-capturing group (?:...) for the overall OR, keep capture groups for specific patterns
TIMESTAMP_REGEX = rf"^(?:{LINUX_TS_PATTERN}|{LINUX_MS_NO_HOUR_TS_PATTERN}|{ISO_OFFSET_PATTERN}|{APACHE_CLF_PATTERN})\s+"

# Log Level (common keywords, flexible delimiters)
LOGLEVEL_REGEX = r"(?:\b|[:\[\(])(DEBUG|INFO|WARNING|WARN|ERROR|ERR|CRITICAL|FATAL|SEVERE)(?:\b|[:\]\)])"
# IPv4 Address
IP_REGEX = r"\b(?:\d{1,3}\.){3}\d{1,3}\b"
# User ID regex: Prioritize user=, then other keys, then phrases, then sshd format
# Group 1: user=... format
# Group 2: uid=/login=/account=... format
# Group 3: phrase format
# Group 4: sshd format
USERID_REGEX = r"(?:user(?:id)?[=:]\s*'?\"?(\w+)'?\"?\b)|(?:(?:uid|login|account)[=:]\s*'?\"?(\w+)'?\"?\b)|(?:(?:Invalid user|(?:Failed password for(?: invalid user)?)|Accepted password for|session opened for user)\s+(\w+)\b)|(?:sshd\\[\\d+\\]:\\s+user\\s+(\\w+))"

# Added patterns for SSH status/auth
LOGIN_STATUS_PATTERNS = {
    'FAILURE_USER': r'Invalid user \w+ from',
    'FAILURE_PWD': r'Failed password for (?:invalid user )?\w+ from',
    'SUCCESS': r'Accepted (password|publickey|keyboard-interactive) for \w+ from',
    'SESSION_START': r'session opened for user \w+',
    'SESSION_END': r'Disconnected from authenticating user \w+ |Disconnected from invalid user \w+ |Received disconnect from',
    'ERROR': r'error: |fatal: ' # General errors
}
AUTH_METHOD_REGEX = r'Accepted (password|publickey|keyboard-interactive) for'

# Helper function for parsing a single line
def parse_log_line(line, ts_pattern):
    # Initialize with new fields
    parsed = {'timestamp': None, 'log_level': None, 'source_ip': None, 'user_id': None, 
              'login_status': 'UNKNOWN', 'auth_method': 'UNKNOWN', # Default new fields
              'message': line.strip()}
    original_line = line
    remaining_line = line.strip()
    
    # 1. Extract Timestamp
    ts_match = re.match(ts_pattern, line)
    if ts_match:
        # Find which group actually matched (captures are index 1, 2, 3...)
        timestamp_str = next((g for g in ts_match.groups() if g is not None), None)
        
        if timestamp_str:
            timestamp_str = timestamp_str.strip()
            parsed_dt = pd.NaT # Initialize as NaT
            try:
                # Attempt direct parsing first (covers ISO, Apache CLF)
                parsed_dt = pd.to_datetime(timestamp_str, errors='raise')
            except ValueError:
                # If direct parsing fails, check standard Linux format 'MMM DD HH:MM:SS'
                linux_format_match = re.match(r"^" + LINUX_TS_PATTERN.strip("()"), timestamp_str)
                if linux_format_match:
                    current_year = datetime.datetime.now().year
                    timestamp_with_year = f"{timestamp_str} {current_year}"
                    try:
                        parsed_dt = pd.to_datetime(timestamp_with_year, format='%b %d %H:%M:%S %Y', errors='raise')
                    except ValueError:
                        parsed_dt = pd.NaT
                else:
                    # Check the new format 'MMM DD MM:SS.ms'
                    linux_ms_format_match = re.match(r"^" + LINUX_MS_NO_HOUR_TS_PATTERN.strip("()"), timestamp_str)
                    if linux_ms_format_match:
                        current_year = datetime.datetime.now().year
                        timestamp_with_year = f"{timestamp_str} {current_year}"
                        try:
                             # Use format string recognizing month, day, minute, second, microsecond, year
                             # Hour will likely default to 00
                            parsed_dt = pd.to_datetime(timestamp_with_year, format='%b %d %M:%S.%f %Y', errors='raise')
                        except ValueError:
                            parsed_dt = pd.NaT
                    else:
                        parsed_dt = pd.NaT # Coerce to NaT if it's not any recognized format
            except Exception:
                 # Catch any other unexpected parsing errors
                 parsed_dt = pd.NaT

            parsed['timestamp'] = parsed_dt

            # If parsing was successful (even after adding year), remove timestamp part from the line
            if pd.notna(parsed['timestamp']):
                 # ts_match.end() gives the end position of the whole matched timestamp + trailing space
                remaining_line = line[ts_match.end():].strip()
                parsed['message'] = remaining_line # Initial message is what's left
            # else: # If parsing failed, keep the original message (already set)
                # pass

    # --- Status/Auth Parsing (BEFORE other parsing on remaining_line) ---
    # Check login status first - order might matter if messages overlap
    status_found = False
    for status, pattern in LOGIN_STATUS_PATTERNS.items():
        if re.search(pattern, original_line, re.IGNORECASE): # Search original line for status context
            parsed['login_status'] = status
            status_found = True
            # If it was a SUCCESS, try to extract auth method
            if status == 'SUCCESS':
                auth_match = re.search(AUTH_METHOD_REGEX, original_line, re.IGNORECASE)
                if auth_match:
                    parsed['auth_method'] = auth_match.group(1).lower()
            break # Stop after first status match
    
    # 2. Extract Log Level
    level_match = re.search(LOGLEVEL_REGEX, remaining_line, re.IGNORECASE)
    if level_match:
        parsed['log_level'] = level_match.group(1).upper()
        # Attempt to remove the full matched level part (e.g., '[INFO]', 'ERROR:')
        # Use level_match.group(0) which is the whole match
        remaining_line = remaining_line.replace(level_match.group(0), '', 1).strip()
        parsed['message'] = remaining_line

    # 3. Extract IP Address
    # Search for IP anywhere, but prioritize removing it only if it's near other structured data (heuristic)
    ip_match = re.search(IP_REGEX, remaining_line)
    if ip_match:
        parsed['source_ip'] = ip_match.group(0)
        # Remove the IP address itself, potentially leaving surrounding text like 'IP: '
        # More advanced removal could try to remove common prefixes/suffixes too.
        remaining_line = remaining_line.replace(ip_match.group(0), '', 1).strip()
        parsed['message'] = remaining_line

    # 4. Extract User ID
    user_match = re.search(USERID_REGEX, remaining_line, re.IGNORECASE)
    if user_match:
        # Check capture groups in order of priority
        user_id = user_match.group(1) or user_match.group(2) or user_match.group(3) or user_match.group(4)
        if user_id: # Ensure we got a user ID
            parsed['user_id'] = user_id
            # Remove the entire matched user identifier string 
            # Use user_match.group(0) which is the whole match
            try:
                # We need to be careful removing group(0) if the match overlaps other info we want
                # For now, attempt removal, but this might need refinement later if it removes too much.
                remaining_line = remaining_line.replace(user_match.group(0), '', 1).strip()
                parsed['message'] = remaining_line
            except Exception: # Handle potential errors if group(0) is complex/problematic
                pass # Keep original remaining_line if replace fails

    # Final message cleanup (remove extra spaces, common delimiters left over)
    # Added '|' to delimiters to remove potential leftovers
    parsed['message'] = re.sub(r'^[ :\-\[\(\|]+', '', parsed['message']).strip()
    
    # Return a dictionary instead of a Series for easier appending to list
    return parsed 

@st.cache_data # Cache the result
def load_and_parse_log_file(uploaded_file, max_lines=None):
    """Reads, parses timestamp, level, IP, user, and message from logs, respecting max_lines."""
    if uploaded_file is None:
        return pd.DataFrame()

    parsed_data = []
    lines_processed = 0
    total_lines_in_file = 0 # Keep track for reporting if limit is hit

    try:
        # Use TextIOWrapper to read line by line with proper decoding
        # Use errors='ignore' to skip problematic characters, alternatives exist
        with io.TextIOWrapper(uploaded_file, encoding='utf-8', errors='ignore') as text_stream:
            for i, line in enumerate(text_stream):
                total_lines_in_file = i + 1
                if max_lines is not None and lines_processed >= max_lines:
                    break # Stop processing if max_lines limit reached
                
                # Parse the line (now returns a dict)
                parsed_line_data = parse_log_line(line, TIMESTAMP_REGEX)
                # Add raw log and line number
                parsed_line_data['raw_log'] = line.strip()
                parsed_line_data['line_number'] = i 
                parsed_data.append(parsed_line_data)
                lines_processed += 1

        if not parsed_data:
            st.warning("No lines were processed. The file might be empty or the format unrecognizable.")
            return pd.DataFrame()

        # Create DataFrame from the list of dictionaries
        df = pd.DataFrame(parsed_data)
        
        # Reorder columns for better display (optional)
        cols_order = ['line_number', 'timestamp', 'log_level', 'source_ip', 'user_id', 'message', 'raw_log']
        df = df[[col for col in cols_order if col in df.columns]]
        
        # Report on parsing success
        st.success(f"Processed {lines_processed} lines." + 
                   (f" (Limited by tier, {total_lines_in_file} total lines in file)" if (max_lines is not None and lines_processed < total_lines_in_file) else ""))
        for col in ['timestamp', 'log_level', 'source_ip', 'user_id']:
            if col in df.columns:
                parsed_count = df[col].notna().sum()
                if parsed_count > 0:
                    st.info(f"Found {col} in {parsed_count}/{lines_processed} processed lines.")
                # else:
                    # Optional: Add message if column exists but nothing found
                    # st.info(f"Did not find {col} in any processed lines using current patterns.")
            # else:
                # Optional: Report if a column wasn't even created (parsing failed entirely?)
                # st.warning(f"Column {col} was not created during parsing.")

        return df

    except UnicodeDecodeError:
        # This might be less likely now with errors='ignore', but kept for safety
        st.error("Error decoding file. Ensure file uses UTF-8 encoding or similar.")
        return pd.DataFrame()
    except Exception as e:
        st.error(f"An error occurred during parsing: {e}")
        return pd.DataFrame()
