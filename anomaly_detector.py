import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import numpy as np
import streamlit as st

# Define base feature types
ALL_FEATURE_TYPES = ['time', 'log_level', 'message_length', 'ip_presence', 'user_presence', 'login_status', 'auth_method']

# Enhanced preprocessing function
def preprocess_for_anomaly(df, selected_feature_types=None):
    """Converts log data into numerical features based on selection."""
    if selected_feature_types is None:
        selected_feature_types = ALL_FEATURE_TYPES # Default to all if none provided
        
    features = pd.DataFrame(index=df.index)
    original_cols = df.columns

    # 1. Time Features (Hour, Minute, Second, DayOfWeek)
    if 'time' in selected_feature_types and 'timestamp' in original_cols:
        temp_timestamps = pd.to_datetime(df['timestamp'], errors='coerce')
        if not temp_timestamps.isna().all():
            features['hour'] = temp_timestamps.dt.hour.fillna(0) # Fill potential NaNs from NaT
            features['minute'] = temp_timestamps.dt.minute.fillna(0)
            features['second'] = temp_timestamps.dt.second.fillna(0)
            features['dayofweek'] = temp_timestamps.dt.dayofweek.fillna(0)
        else:
            # Add dummy columns if time selected but timestamps invalid/missing
            features['hour'] = 0
            features['minute'] = 0
            features['second'] = 0
            features['dayofweek'] = 0
    elif 'time' in selected_feature_types: # If 'time' selected but no 'timestamp' col
        features['hour'] = 0
        features['minute'] = 0
        features['second'] = 0
        features['dayofweek'] = 0

    # 2. Log Level Features (One-Hot Encoding)
    # We generate these if 'log_level' is selected, ensuring consistent columns for the model
    if 'log_level' in selected_feature_types and 'log_level' in original_cols:
        log_levels = df['log_level'].fillna('UNKNOWN').astype(str)
        # Define expected levels to ensure consistent feature set
        expected_levels = ['DEBUG', 'INFO', 'WARNING', 'WARN', 'ERROR', 'ERR', 'CRITICAL', 'FATAL', 'SEVERE', 'UNKNOWN'] # Base levels
        level_dummies = pd.get_dummies(log_levels).reindex(columns=expected_levels, fill_value=0)
        level_dummies.columns = ['level_' + col for col in level_dummies.columns] # Prefix columns
        features = pd.concat([features, level_dummies], axis=1)
    elif 'log_level' in selected_feature_types: # If selected but no log_level column
        # Add dummy zero columns for all expected levels
        expected_levels = ['DEBUG', 'INFO', 'WARNING', 'WARN', 'ERROR', 'ERR', 'CRITICAL', 'FATAL', 'SEVERE', 'UNKNOWN']
        for level in expected_levels:
             features[f'level_{level}'] = 0

    # 3. Message Length Feature
    if 'message_length' in selected_feature_types and 'message' in original_cols:
        # Ensure message is string, handle potential NaN/None
        features['message_length'] = df['message'].fillna('').astype(str).str.len()
    elif 'message_length' in selected_feature_types:
        features['message_length'] = 0

    # 4. IP Presence Feature (Binary)
    if 'ip_presence' in selected_feature_types and 'source_ip' in original_cols:
        features['ip_present'] = df['source_ip'].notna().astype(int)
    elif 'ip_presence' in selected_feature_types:
         features['ip_present'] = 0

    # 5. User Presence Feature (Binary)
    if 'user_presence' in selected_feature_types and 'user_id' in original_cols:
        features['user_present'] = df['user_id'].notna().astype(int)
    elif 'user_presence' in selected_feature_types:
        features['user_present'] = 0
        
    # 6. Login Status Features (One-Hot Encoding)
    if 'login_status' in selected_feature_types and 'login_status' in original_cols:
        status_col = df['login_status'].fillna('UNKNOWN').astype(str)
        # Define expected statuses for consistent columns
        expected_statuses = ['SUCCESS', 'FAILURE_PWD', 'FAILURE_USER', 'SESSION_START', 'SESSION_END', 'ERROR', 'UNKNOWN']
        status_dummies = pd.get_dummies(status_col).reindex(columns=expected_statuses, fill_value=0)
        status_dummies.columns = ['status_' + col for col in status_dummies.columns] # Prefix
        features = pd.concat([features, status_dummies], axis=1)
    elif 'login_status' in selected_feature_types: # If selected but no column
        expected_statuses = ['SUCCESS', 'FAILURE_PWD', 'FAILURE_USER', 'SESSION_START', 'SESSION_END', 'ERROR', 'UNKNOWN']
        for status in expected_statuses:
            features[f'status_{status}'] = 0

    # 7. Auth Method Features (One-Hot Encoding)
    if 'auth_method' in selected_feature_types and 'auth_method' in original_cols:
        auth_col = df['auth_method'].fillna('UNKNOWN').astype(str)
        # Define expected methods
        expected_methods = ['password', 'publickey', 'keyboard-interactive', 'UNKNOWN'] # Add more if needed
        auth_dummies = pd.get_dummies(auth_col).reindex(columns=expected_methods, fill_value=0)
        auth_dummies.columns = ['auth_' + col for col in auth_dummies.columns] # Prefix
        features = pd.concat([features, auth_dummies], axis=1)
    elif 'auth_method' in selected_feature_types: # If selected but no column
        expected_methods = ['password', 'publickey', 'keyboard-interactive', 'UNKNOWN']
        for method in expected_methods:
            features[f'auth_{method}'] = 0
        
    # Handle cases where no features were selected or generated
    if features.empty:
        st.warning("No features selected or generated for anomaly detection.")
        # Return an empty DataFrame and None for scaler AND scaled_features
        return pd.DataFrame(), None, None # Return 3 values consistent with other path

    # --- Scaling --- 
    # Ensure all features are numeric and handle NaNs before scaling
    features = features.apply(pd.to_numeric, errors='coerce').fillna(0) 
    scaler = StandardScaler()
    scaled_features = scaler.fit_transform(features)
    
    # Return features df for inspection AND scaled_features for model
    return features, scaled_features, scaler

# Anomaly detection function (Isolation Forest)
def detect_anomalies(original_df, scaled_features, contamination='auto'):
    """Detects anomalies using Isolation Forest."""
    if scaled_features is None or scaled_features.shape[0] == 0 or scaled_features.shape[1] == 0:
        st.warning("Cannot run anomaly detection with no features.")
        # Return original df with an empty 'anomaly_detected' column
        original_df['anomaly_detected'] = False 
        return original_df
        
    # Contamination needs to be float > 0 and <= 0.5 if not 'auto'
    try:
        cont_float = float(contamination)
        if not (0 < cont_float <= 0.5):
            st.warning(f"Contamination rate ({cont_float}) out of range (0, 0.5]. Using 'auto'.")
            contamination = 'auto'
        else:
             contamination = cont_float
    except ValueError:
        if contamination != 'auto':
            st.warning(f"Invalid contamination value '{contamination}'. Using 'auto'.")
            contamination = 'auto'

    model = IsolationForest(contamination=contamination, random_state=42)
    predictions = model.fit_predict(scaled_features)
    
    # Add predictions to the original DataFrame (-1 for anomaly, 1 for normal)
    results_df = original_df.copy()
    results_df['anomaly_score'] = model.decision_function(scaled_features)
    results_df['anomaly_detected'] = predictions == -1 # True for anomalies
    
    return results_df

# Removing cache decorator permanently to fix prediction count mismatch on tier change
def detect_anomalies_isoforest(_processed_data, contamination='auto'):
    """Detects anomalies using Isolation Forest.
    
    Args:
        _processed_data: NumPy array of preprocessed numerical features.
        contamination: The expected proportion of outliers in the data set.
                       'auto' lets the algorithm estimate it.
    
    Returns:
        NumPy array: An array containing anomaly scores (-1 for outliers, 1 for inliers).
    """
    if _processed_data is None or _processed_data.shape[0] == 0:
        st.info("No data provided for anomaly detection.")
        return np.array([]) # Return empty array
        
    if _processed_data.shape[0] == 1:
        st.warning("Anomaly detection requires more than one data point. Skipping.")
        # Return an array indicating 'inlier' for the single point
        return np.array([1])
        
    try:
        model = IsolationForest(contamination=contamination, random_state=42)
        # Fit the model and predict outliers
        # Prediction returns 1 for inliers, -1 for outliers.
        predictions = model.fit_predict(_processed_data)
        return predictions
    except ValueError as e:
        st.error(f"Error during Isolation Forest fitting/prediction: {e}. Ensure data is numeric.")
        return np.array([])
    except Exception as e:
        st.error(f"An unexpected error occurred during anomaly detection: {e}")
        return np.array([])
