# LogHunter AI 🛡️

LogHunter AI is an intelligent log analysis tool built with Python and Streamlit. It helps users parse, visualize, detect anomalies in, and understand log files using machine learning and large language models (LLMs).

**(Consider adding a screenshot/GIF of the app here)**

## Features

*   **Log Upload & Parsing:** Upload `.log` or `.txt` files. The tool parses timestamps (various formats, including Linux syslog), log levels (if present), source IPs, user IDs (from multiple contexts like `user=`, `uid=`, `sshd[pid]: user ...`, `Failed password for ...`), and SSH-specific events (login success/failure, session start/end).
*   **Configurable Anomaly Detection:**
    *   Uses Scikit-learn's `IsolationForest` algorithm.
    *   Select features for detection: time components, message length, IP/user presence, log level, login status, authentication method.
    *   Adjust sensitivity using the "Expected Anomaly Rate (%)" slider.
*   **AI-Powered Insights:**
    *   **Summarization:** Get a concise summary of the log file using OpenAI or a local Ollama instance.
    *   **Explanation:** Select a detected anomaly and request an AI explanation for why it might be suspicious.
    *   *(Requires API key for OpenAI or a running Ollama instance)*.
*   **Interactive Visualization & Review:**
    *   **Raw Data Tab:** View parsed logs with pagination.
    *   **Anomaly Detection Tab:**
        *   View overall statistics and charts (log level distribution, anomaly timeline, top anomalous IPs/users).
        *   Filter detected anomalies by log level, source IP, user ID, and date range.
        *   Review anomalies in a paginated table, mark them as True/False Positives.
        *   Export filtered anomalies as CSV or JSON Lines.
    *   **AI Summary Tab:** View generated summaries.
*   **Tier Simulation:** Simulate different usage tiers (Free, Pro, Team) to see how log line limits and AI feature availability (for OpenAI) change.
*   **Performance:** Optimized for handling large log files by processing line-by-line up to the selected tier's limit.

## Tech Stack

*   **Python 3.x**
*   **Streamlit:** Web application framework
*   **Pandas:** Data manipulation
*   **Scikit-learn:** Anomaly detection (IsolationForest), data scaling
*   **Plotly:** Interactive visualizations
*   **Numpy:** Numerical operations
*   **OpenAI:** For interacting with OpenAI API (optional)
*   **Requests:** For interacting with Ollama API (optional)
*   **Python-Dotenv:** Environment variable management

## Setup

1.  **Clone the Repository:**
    ```bash
    git clone https://github.com/StavrosKost/LogHunterAI.git
    ```
2.  **Create a Virtual Environment (Recommended):**
    ```bash
    python -m venv venv
    # On Windows
    venv\Scripts\activate
    # On macOS/Linux
    source venv/bin/activate
    ```
3.  **Install Dependencies:**
    ```bash
    pip install -r requirements.txt
    ```
    *(Note: You'll need to create a `requirements.txt` file. I can help with that if you don't have one yet!)*
4.  **Environment Variables (Optional - for AI Features):**
    *   Create a file named `.env` in the root project directory.
    *   **For OpenAI:** Add your API key:
        ```
        OPENAI_API_KEY='your_openai_api_key_here'
        ```
    *   **For Ollama:** Ensure your Ollama instance is running locally (usually at `http://localhost:11434`). The tool uses this default address.

## Running the Application

1.  Make sure your virtual environment is activated.
2.  Navigate to the project's root directory in your terminal.
3.  Run the Streamlit application:
    ```bash
    streamlit run Home.py
    ```
4.  The application should open in your default web browser.

## Usage

1.  **Upload Log File:** Use the sidebar "Upload Log File" button.
2.  **Configure (Sidebar):**
    *   *(Optional)* Simulate User Tier.
    *   *(Optional)* Select features for anomaly detection.
    *   *(Optional)* Adjust the "Expected Anomaly Rate (%)" slider.
    *   *(Optional)* Choose AI Provider (OpenAI/Ollama).
3.  **Run Analysis:** Click the "Run Anomaly Detection" button in the sidebar.
4.  **Explore Tabs:**
    *   **Raw Data:** Browse the parsed log data with pagination.
    *   **Anomaly Detection:** View charts, filter anomalies, review the anomaly table, and use the "Explain Anomaly" feature.
    *   **AI Summary:** Generate and view an AI summary of the logs.

## Future Improvements

*   Support for more log formats and automatic format detection.
*   More sophisticated anomaly detection features (e.g., TF-IDF, sequence analysis).
*   User accounts and persistent storage (for a web service model).
*   Enhanced visualization options.
*   Refined error handling.

## Contributing
Currently, feedback and bug reports via GitHub Issues are most welcome!

## A comment about the requirements.txt file
pywin32 it is not supported in streamlit
but i do use it inside the app to process windows log.
