import os
import openai
from dotenv import load_dotenv
import streamlit as st
import pandas as pd
import json # Needed for Ollama payload
import urllib.request # Needed for Ollama requests
import urllib.error # Needed for Ollama error handling

# Load environment variables from .env file
load_dotenv()

# Configure OpenAI API key
api_key = os.getenv("OPENAI_API_KEY")
if api_key:
    openai.api_key = api_key
else:
    pass

def summarize_logs_openai(log_data_str, model="gpt-3.5-turbo", max_tokens=150):
    """Summarizes the provided log data string using the OpenAI API."""
    if not api_key:
        st.error("OPENAI_API_KEY not found in environment variables. Please set it in your .env file.")
        return "Error: OpenAI API key not configured."
    if not log_data_str:
        return "No log data provided for summarization."

    try:
        # Ensure log_data_str is reasonably sized to avoid excessive API costs/limits
        # You might want to truncate or sample if it's very large
        max_input_length = 4000 # Example limit, adjust as needed
        if len(log_data_str) > max_input_length:
            log_data_str = log_data_str[:max_input_length] + "... [truncated]"
            st.warning(f"Log data truncated to {max_input_length} characters for summarization.")

        response = openai.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": "You are a helpful assistant designed to summarize log files concisely, highlighting potential issues or anomalies."},
                {"role": "user", "content": f"Please summarize the following log data:\n\n{log_data_str}"}
            ],
            max_tokens=max_tokens,
            temperature=0.5, # Adjust for creativity vs. factuality
        )
        summary = response.choices[0].message.content.strip()
        return summary
    except openai.AuthenticationError:
         st.error("OpenAI Authentication Error: Check your API key.")
         return "Error: OpenAI authentication failed."
    except openai.RateLimitError:
        st.error("OpenAI Rate Limit Error: You have exceeded your quota or rate limit.")
        return "Error: OpenAI rate limit exceeded."
    except Exception as e:
        st.error(f"An error occurred during summarization: {e}")
        return f"Error during summarization: {e}"

def explain_anomaly_openai(log_entry, model="gpt-3.5-turbo", max_tokens=100):
    """
    Uses OpenAI to provide a potential explanation for why a log entry might be anomalous.

    Args:
        log_entry (pd.Series or dict): A dictionary or Pandas Series containing details
                                        of a single log entry (e.g., timestamp, log_level,
                                        source_ip, user_id, message).
        model (str): The OpenAI model to use.
        max_tokens (int): The maximum number of tokens for the explanation.

    Returns:
        str: The AI-generated explanation or an error message.
    """
    # --- Temporary Debugging --- #
    # print(f"[DEBUG] Using OpenAI Key: {api_key[:5]}...{api_key[-4:] if api_key else 'None'}") 
    # --- End Debugging --- #

    if not api_key:
        # Use st.error since this will be called from the Streamlit app context
        st.error("OPENAI_API_KEY not found. Cannot get AI explanation.")
        return "Error: OpenAI API key not configured."
    # Correctly check if log_entry is None OR an empty Series
    if log_entry is None or (isinstance(log_entry, pd.Series) and log_entry.empty):
        return "Error: No log entry data provided for explanation."

    # Construct a detailed prompt
    prompt_context = ("You are a cybersecurity analyst assistant. Analyze the following log entry, "
                      "which was flagged as a potential anomaly by a machine learning model. "
                      "Provide a concise explanation (1-2 sentences) of *why* this specific entry "
                      "might be considered suspicious or anomalous, focusing on common security concerns related to the log content.")

    # Format the log entry details for the prompt
    log_details = ""
    details_dict = log_entry.to_dict() if isinstance(log_entry, pd.Series) else log_entry

    # Include key fields if they exist
    for key in ['timestamp', 'log_level', 'source_ip', 'user_id', 'message', 'raw_log']:
        if key in details_dict and pd.notna(details_dict[key]):
            log_details += f"- {key.replace('_', ' ').title()}: {details_dict[key]}\n"

    if not log_details:
         return "Error: Could not extract details from log entry for explanation."

    user_prompt = f"Log Entry Details:\n{log_details}\n\nPotential Reason for Anomaly Flag:"

    try:
        response = openai.chat.completions.create(
            model=model,
            messages=[
                {"role": "system", "content": prompt_context},
                {"role": "user", "content": user_prompt}
            ],
            max_tokens=max_tokens,
            temperature=0.3, # Lower temperature for more factual explanation
        )
        explanation = response.choices[0].message.content.strip()
        return explanation
    except openai.AuthenticationError:
        st.error("OpenAI Authentication Error: Check your API key.")
        return "Error: OpenAI authentication failed."
    except openai.RateLimitError:
        st.error("OpenAI Rate Limit Error: You have exceeded your quota or rate limit.")
        return "Error: OpenAI rate limit exceeded."
    except Exception as e:
        st.error(f"An error occurred during explanation generation: {e}")
        return f"Error generating explanation: {e}"

# --- Ollama Functions --- #

OLLAMA_ENDPOINT = "http://localhost:11434/api/generate" # Default Ollama API endpoint

def _call_ollama(payload):
    """Helper function to make a POST request to the Ollama endpoint."""
    try:
        json_payload = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(OLLAMA_ENDPOINT, data=json_payload, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req) as response:
            if response.status == 200:
                response_body = response.read().decode('utf-8')
                # Ollama streams responses line-by-line JSON; parse the final one
                # For non-streaming (stream=False), it should be a single JSON object
                try:
                    # Try parsing the entire response as a single JSON object first
                    data = json.loads(response_body)
                    return data.get('response', "Error: No 'response' key found in Ollama output."), None
                except json.JSONDecodeError:
                     # Fallback for potentially incomplete stream (shouldn't happen with stream=False but safe)
                     lines = response_body.strip().split('\n')
                     final_data = json.loads(lines[-1])
                     return final_data.get('response', "Error: No 'response' key found in final Ollama output."), None

            else:
                return None, f"Ollama API request failed with status code {response.status}. Is Ollama running?"
    except urllib.error.URLError as e:
        return None, f"Error connecting to Ollama at {OLLAMA_ENDPOINT}. Is Ollama running? ({e})"
    except Exception as e:
        return None, f"An unexpected error occurred while calling Ollama: {e}"

def summarize_logs_ollama(log_data_str, model="llama2", max_tokens=150):
    """Summarizes log data using a local Ollama model."""
    if not log_data_str:
        return "No log data provided for summarization."

    # Simple truncation if needed (Ollama handles context differently, but good practice)
    max_input_length = 4000
    if len(log_data_str) > max_input_length:
        log_data_str = log_data_str[:max_input_length] + "... [truncated]"
        st.warning(f"Log data truncated to {max_input_length} characters for summarization.")

    prompt = f"Summarize the key events and potential security issues in the following log data concisely:\n\n{log_data_str}\n\nSummary:"

    payload = {
        "model": model,
        "prompt": prompt,
        "stream": False, # Get the full response at once
        "options": {
            "num_predict": max_tokens # Approximate control over output length
        }
    }

    summary, error = _call_ollama(payload)
    if error:
        st.error(error)
        return f"Error: {error}"
    return summary

def explain_anomaly_ollama(log_entry, model="llama2", max_tokens=100):
    """Explains a log anomaly using a local Ollama model."""
    if log_entry is None or (isinstance(log_entry, pd.Series) and log_entry.empty):
        return "Error: No log entry data provided for explanation."

    # Construct prompt for Ollama
    prompt_context = ("Analyze the following log entry flagged as a potential anomaly. "
                      "Explain concisely (1-2 sentences) why it might be suspicious based on security concerns.")

    log_details = ""
    details_dict = log_entry.to_dict() if isinstance(log_entry, pd.Series) else log_entry
    for key in ['timestamp', 'log_level', 'source_ip', 'user_id', 'message', 'raw_log']:
        if key in details_dict and pd.notna(details_dict[key]):
            log_details += f"- {key.replace('_', ' ').title()}: {details_dict[key]}\n"

    if not log_details:
         return "Error: Could not extract details from log entry for explanation."

    user_prompt = f"{prompt_context}\n\nLog Entry Details:\n{log_details}\n\nPotential Reason for Anomaly Flag:"

    payload = {
        "model": model,
        "prompt": user_prompt,
        "stream": False,
        "options": {
            "num_predict": max_tokens
        }
    }

    explanation, error = _call_ollama(payload)
    if error:
        st.error(error)
        return f"Error: {error}"
    return explanation
