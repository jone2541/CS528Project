#!/usr/bin/env python3
# sudo apt-get install python3
# chmod 755 project.py
#refence to my implimentation for me CS541 and CS529 projects for ML
import argparse
import sqlite3
import time
import threading
import os
from collections import defaultdict, deque, Counter
import sys
import math
import warnings 
from scapy.all import sniff, DNS, DNSQR, DNSRR, IP, UDP
import pandas as pd
from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix
import joblib
import numpy as np

#Configuration Constants
DEFAULT_INTERFACE = "eth0"
DEFAULT_DB_FILE = "dns_agent_data.db"
DEFAULT_MODEL_FILE = "dns_anomaly_model.joblib"
DEFAULT_SCALER_FILE = "dns_feature_scaler.joblib"
DEFAULT_ALERT_LOG_FILE = "dns_alerts.log"
DEFAULT_TEST_SPLIT = 0.2
TIME_WINDOW_SECONDS = 5
MAX_QUEUE_SIZE = 2000

FEATURES = [
    'responses_in_window',
    'unique_src_ips_in_window',
    'unique_txids_in_window',
    'response_code',
    'qname_entropy_mean_in_window',   
    'qname_entropy_stddev_in_window'  
] 
LABEL_COLUMN = 'label'

# --- Global State ---
recent_responses = defaultdict(lambda: deque(maxlen=MAX_QUEUE_SIZE))
state_lock = threading.Lock()

#Helper Function for Entropy
def calculate_entropy(text):
    if not text: return 0.0
    counts = Counter(text)
    text_len = float(len(text))
    entropy = 0.0
    for count in counts.values():
        p_x = count / text_len
        if p_x > 0: entropy -= p_x * math.log2(p_x)
    return entropy

#Database Setup Function
def setup_database(db_file):
    """Creates the features and alerts tables"""
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        # Create features table
        cursor.execute(f"""
            CREATE TABLE IF NOT EXISTS dns_features (
                timestamp REAL PRIMARY KEY,
                query_name TEXT,
                query_type INTEGER,
                response_src_ip TEXT,
                response_txid INTEGER,
                response_code INTEGER,
                responses_in_window INTEGER,
                unique_src_ips_in_window INTEGER,
                unique_txids_in_window INTEGER,
                pkt_qname_entropy REAL,           
                qname_entropy_mean_in_window REAL,
                qname_entropy_stddev_in_window REAL, 
                {LABEL_COLUMN} INTEGER DEFAULT 0
            )
        """)
        print(f"Table 'dns_features' ensured in database '{db_file}'.")

        # Alerts table 
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp REAL,
                alert_message TEXT,
                query_name TEXT,
                response_src_ip TEXT,
                response_txid INTEGER,
                responses_in_window INTEGER,
                unique_src_ips_in_window INTEGER,
                unique_txids_in_window INTEGER
            )
        """)
        print(f"Table 'alerts' ensured in database '{db_file}'.")

        conn.commit()
        conn.close()
        print(f"Database '{db_file}' setup complete.")
    except sqlite3.Error as e:
        print(f"Database error during setup of '{db_file}': {e}")
        raise

# --- calculate_window_features---
# Assists with creating statistics of queries, and tracking frequency
def calculate_window_features(query_name, current_time):
    """Calculates aggregate features"""
    responses = 0
    unique_src_ips = set()
    unique_txids = set()
    entropies_in_window = [] # Store valid entropies

    if query_name in recent_responses:
        window_start_time = current_time - TIME_WINDOW_SECONDS
        # Assumes deque stores: (timestamp, src_ip, txid, rcode, qname_entropy)
        relevant_responses = [
            resp for resp in recent_responses[query_name] if resp[0] >= window_start_time
        ]
        responses = len(relevant_responses)

        for ts, src_ip, txid, rcode, q_entropy in relevant_responses: # Unpack 
            unique_src_ips.add(src_ip)
            unique_txids.add(txid)
            entropies_in_window.append(q_entropy)

    # Calculate Entropy statistics
    if entropies_in_window:
        entropy_mean = np.mean(entropies_in_window)
        entropy_stddev = np.std(entropies_in_window)
    else:
        entropy_mean = 0.0
        entropy_stddev = 0.0

    # Return windowed features
    return (responses, len(unique_src_ips), len(unique_txids),
            entropy_mean, entropy_stddev) 

#log_alert function
# Creates a log entry to the file system, and adds it to the DB
def log_alert(timestamp, message, qname, src_ip, txid, resp_count, unique_ips, unique_txids, alert_log_file, db_file):
    log_entry = f"{time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(timestamp))} | {message}\n"
    print(f"ALERT: {log_entry.strip()}")
    try:
        with open(alert_log_file, "a") as f: f.write(log_entry)
    except IOError as e: print(f"Failed to write to alert log file {alert_log_file}: {e}")
    try:
        conn = sqlite3.connect(db_file)
        cursor = conn.cursor()
        cursor.execute("""INSERT INTO alerts (timestamp, alert_message, query_name, response_src_ip, response_txid, responses_in_window, unique_src_ips_in_window, unique_txids_in_window)
                          VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                       (timestamp, message, qname, src_ip, txid, resp_count, unique_ips, unique_txids))
        conn.commit()
        conn.close()
    except sqlite3.Error as e: print(f"Failed to write alert to database table 'alerts' in {db_file}: {e}")


# Packet Processing for collect
# Sniffs each packet on the interface, and formats it into the database
def process_packet_collect(packet, db_file, label_value):
    """Callback for sniff in 'collect' mode"""
    global recent_responses
    if not packet.haslayer(DNS) or not packet.haslayer(IP) or not packet.haslayer(UDP): return

    ip_layer = packet.getlayer(IP)
    dns_layer = packet.getlayer(DNS)

    if dns_layer.qr == 1 and dns_layer.qdcount > 0 and dns_layer.qd:
        query = dns_layer.qd[0]
        qtype = query.qtype
        txid = dns_layer.id
        rcode = dns_layer.rcode
        src_ip = ip_layer.src
        timestamp = time.time()
        hostname_part = ""
        try:
            qname = query.qname.decode('utf-8', errors='ignore').rstrip('.')
            parts = qname.split('.')
            if len(parts) > 0: hostname_part = parts[0]
        except AttributeError:
            qname = "decoding_error"; hostname_part = ""
        # --- Calculate Entropy ---
        pkt_qname_entropy = calculate_entropy(hostname_part)
        with state_lock:
            # Update recent responses
            q_responses = recent_responses[qname]
            # Append tuple: (timestamp, src_ip, txid, rcode, qname_entropy)
            q_responses.append((timestamp, src_ip, txid, rcode, pkt_qname_entropy))

            # Calculate features 
            (resp_count, unique_ips, unique_txids,
             entropy_mean, entropy_stddev) = calculate_window_features(qname, timestamp)

        # Log extracted features to the database
        try:
            conn = sqlite3.connect(db_file)
            cursor = conn.cursor()
            cursor.execute(f'''INSERT INTO dns_features (
                                timestamp, query_name, query_type, response_src_ip, response_txid,
                                response_code, pkt_qname_entropy, -- Removed response_ttl
                                responses_in_window, unique_src_ips_in_window, unique_txids_in_window,
                                qname_entropy_mean_in_window, qname_entropy_stddev_in_window, 
                                {LABEL_COLUMN}
                               )
                               VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?) 
                               ON CONFLICT(timestamp) DO NOTHING''',
                           (timestamp, qname, qtype, src_ip, txid,
                            rcode, pkt_qname_entropy, 
                            resp_count, unique_ips, unique_txids,
                            entropy_mean, entropy_stddev, 
                            label_value))
            conn.commit()
            conn.close()
        except sqlite3.Error as e: print(f"Database error during feature logging into {db_file}: {e}")
        except Exception as e: print(f"Unexpected error during feature logging: {e}")

# Process_packet_detect
#sniffs on an interface, process each packet, uses the model to predict if its an attack
def process_packet_detect(packet, model, scaler, alert_log_file, db_file):
    """Callback for sniff in 'detect' mode"""
    global recent_responses
    if not packet.haslayer(DNS) or not packet.haslayer(IP) or not packet.haslayer(UDP): return

    ip_layer = packet.getlayer(IP)
    dns_layer = packet.getlayer(DNS)

    if dns_layer.qr == 1 and dns_layer.qdcount > 0 and dns_layer.qd:
        query = dns_layer.qd[0]
        txid = dns_layer.id
        rcode = dns_layer.rcode
        src_ip = ip_layer.src
        timestamp = time.time()
        hostname_part = ""
        try:
            qname = query.qname.decode('utf-8', errors='ignore').rstrip('.')
            parts = qname.split('.')
            if len(parts) > 0: hostname_part = parts[0]
        except AttributeError: qname = "decoding_error"; hostname_part = ""

        # --- Calculate Entropy ---
        pkt_qname_entropy = calculate_entropy(hostname_part)

        with state_lock:
            q_responses = recent_responses[qname]
            # Append tuple: (timestamp, src_ip, txid, rcode, qname_entropy)
            q_responses.append((timestamp, src_ip, txid, rcode, pkt_qname_entropy)) # Removed pkt_ttl

            # Calculate windowed features - NO TTL stats returned
            (resp_count, unique_ips, unique_txids,
             entropy_mean, entropy_stddev) = calculate_window_features(qname, timestamp)
        current_features_list = [
            resp_count,      # Index 0
            unique_ips,      # Index 1
            unique_txids,    # Index 2
            rcode,           # Index 3 ('response_code')
            entropy_mean,    # Index 4
            entropy_stddev   # Index 5
        ] 
        try:
            # Using DataFrame to avoid feature name warning
            current_features_df = pd.DataFrame([current_features_list], columns=FEATURES)
            scaled_features = scaler.transform(current_features_df)
            scaled_features_np = scaled_features if isinstance(scaled_features, np.ndarray) else scaled_features.to_numpy()
            prediction = model.predict(scaled_features_np)

            if prediction == -1:
                alert_msg = (f"Potential DNS Anomaly Detected for query '{qname}'. Src: {src_ip}, TXID: {txid}. "
                             f"Window Stats: Resp={resp_count}, IPs={unique_ips}, TXIDs={unique_txids}, RCode={rcode}. "
                             f"Entropy Stats: Mean={entropy_mean:.2f}, StdDev={entropy_stddev:.2f}") # Removed TTL info
                log_alert(timestamp, alert_msg, qname, src_ip, txid, resp_count, unique_ips, unique_txids, alert_log_file, db_file)

        except ValueError as e:
             expected_num_features = len(FEATURES)
             if f"X has {len(current_features_list)} features, but StandardScaler is expecting {expected_num_features} features as input" in str(e) or \
                f"X has shape (1,{len(current_features_list)}) but the estimator is expecting (1,{expected_num_features})" in str(e):
                  print(f"FATAL ERROR: Feature mismatch during prediction!")
                  print(f"Features expected (from FEATURES list): {expected_num_features}")
                  print(f"Features provided: {len(current_features_list)}")
                  print(f"Provided list: {current_features_list}")
                  print(f"Check FEATURES list and current_features_list assembly in process_packet_detect.")
             else:
                  print(f"ValueError during scaling/prediction: {e}. Data: {current_features_list}")
        except Exception as e:
            print(f"Error during prediction or scaling: {e}")



# run_training for the mode
def run_training(db_file, model_file, scaler_file, test_split_ratio):
    global args
    print(f"--- Starting Model Training Mode ---")
    print(f"Loading data from: {db_file} (table: dns_features)")
    print(f"Saving model to: {model_file}")
    print(f"Saving scaler to: {scaler_file}")
    print(f"Test split ratio: {test_split_ratio:.1%}")
    contamination_value = args.contamination if args and hasattr(args, 'contamination') else 0.3
    print(f"Using contamination factor: {contamination_value}")
    print(f"Using FEATURES: {FEATURES}") # Print features being used

    if not os.path.exists(db_file): print(f"Error: DB '{db_file}' not found."); return

    # --- Load Data ---
    try:
        conn = sqlite3.connect(db_file)
        columns_to_select = FEATURES + [LABEL_COLUMN] 
        print(f"Attempting to load columns: {', '.join(columns_to_select)}")
        df_all = pd.read_sql_query(f"SELECT {', '.join(columns_to_select)} FROM dns_features", conn)
        conn.close()
        print(f"Loaded {len(df_all)} total records from 'dns_features'.")
        print(f"Columns loaded: {df_all.columns.tolist()}")
    except (sqlite3.Error, pd.io.sql.DatabaseError) as e: # (Error handling)
        print(f"Database/SQL error loading data: {e}")
        return
    except Exception as e: print(f"Error loading data: {e}"); return

    # --- Data Prep ---
    df_all = df_all.dropna(subset=FEATURES + [LABEL_COLUMN])
    print(f"Using {len(df_all)} records after dropping NA.")
    df_labeled = df_all[df_all[LABEL_COLUMN].isin([0, 1])].copy()
    normal_count = (df_labeled[LABEL_COLUMN] == 0).sum()
    attack_count = (df_labeled[LABEL_COLUMN] == 1).sum()
    print(f"Found {len(df_labeled)} explicitly labeled records ({normal_count} Normal, {attack_count} Attack).")
    if df_labeled.empty: print("Error: No labeled data found."); return
    if normal_count == 0 or attack_count == 0:
        print(f"Warning: Found only one label type. Disabling test split."); test_split_ratio = 0.0

    X_labeled = df_labeled[FEATURES] 
    y_labeled = df_labeled[LABEL_COLUMN]

    # --- Train/Test Split --- 
    X_train, X_test, y_train, y_test = None, None, None, None
    perform_testing = test_split_ratio > 0
    if perform_testing:
        try:
            X_train, X_test, y_train, y_test = train_test_split(X_labeled, y_labeled, test_size=test_split_ratio, random_state=42, stratify=y_labeled)
            print(f"Split data: {len(X_train)} train, {len(X_test)} test.")
            print(f"Train labels: Normal: {(y_train == 0).sum()}, Attack: {(y_train == 1).sum()}")
            print(f"Test labels: Normal: {(y_test == 0).sum()}, Attack: {(y_test == 1).sum()}")
        except ValueError as e: print(f"Split Error: {e}. Training on all data."); perform_testing = False; X_train, y_train = X_labeled, y_labeled
    else: print("Skipping test split."); X_train, y_train = X_labeled, y_labeled
    if X_train.empty: print("Error: No training data."); return

    # --- Scale Features ---
    print("Scaling features")
    scaler = StandardScaler()
    try:
        X_train_scaled = scaler.fit_transform(X_train) # Fit/transform DataFrame X_train
        X_test_scaled = scaler.transform(X_test) if perform_testing and X_test is not None and not X_test.empty else None
    except Exception as e: print(f"Error scaling features: {e}"); return

    # --- Train Model ---
    print("Training Isolation Forest model on training data...")
    model = IsolationForest(n_estimators=100, contamination=contamination_value, random_state=42, n_jobs=-1)
    try: model.fit(X_train_scaled) # Train on scaled numpy array
    except Exception as e: print(f"Error training model: {e}"); return

    # Test Model
    if perform_testing and X_test_scaled is not None and y_test is not None:
        print("\n--- Evaluating Model on Test Set ---")
        try:
            predictions = model.predict(X_test_scaled)
            pred_labels = np.array([0 if p == 1 else 1 for p in predictions])
            print("Confusion Matrix (Rows: True, Cols: Predicted):")
            cm = confusion_matrix(y_test.to_numpy(), pred_labels, labels=[0, 1])
            print("           Pred Normal | Pred Attack")
            print(f"True Normal: {cm[0,0]:>9} | {cm[0,1]:>11}")
            print(f"True Attack: {cm[1,0]:>9} | {cm[1,1]:>11}")
            print("\nClassification Report:")
            report = classification_report(y_test.to_numpy(), pred_labels, labels=[0, 1], target_names=['Normal (0)', 'Anomaly (1)'], zero_division=0)
            print(report)
        except Exception as e: print(f"Error during model evaluation: {e}")

    # --- Save Model and Scaler --- 
    try:
        print(f"\nSaving model trained on {len(X_train)} samples to {model_file}")
        joblib.dump(model, model_file)
        print(f"Saving scaler fitted on training data to {scaler_file}")
        joblib.dump(scaler, scaler_file)
        print("--- Training Complete ---")
    except Exception as e: print(f"Error saving model/scaler: {e}")


# run_detection mode
def run_detection(interface, model_file, scaler_file, alert_log_file, db_file):
    global FEATURES # Access the FEATURES list
    print(f"--- Starting Detection Mode ---")
    print(f"Interface: {interface}")
    print(f"Loading model: {model_file}")
    print(f"Loading scaler: {scaler_file}")
    print(f"Using database file: {db_file} (for alerts)")
    print(f"Logging alerts to file: {alert_log_file}")
    print(f"Expecting features: {FEATURES}") # Print features expected by detection

    # --- Load Model and Scaler ---
    try:
        if not os.path.exists(model_file) or not os.path.exists(scaler_file):
            raise FileNotFoundError("Model or scaler file not found.")
        model = joblib.load(model_file)
        scaler = joblib.load(scaler_file)
        # Check feature count consistency
        if hasattr(scaler, 'n_features_in_'):
             expected_features = scaler.n_features_in_
             print(f"Scaler expects {expected_features} features.")
             if expected_features != len(FEATURES): # Compare against current FEATURES list length
                  print(f"FATAL ERROR: Length of FEATURES list ({len(FEATURES)}) does not match scaler expected features ({expected_features}).")
                  print("Ensure FEATURES list is identical between training and detection, and the loaded scaler/model were trained with this list.")
                  sys.exit(1)
        else: print("Warning: Could not determine expected number of features from scaler.")
        print("Model and scaler loaded successfully.")
    except FileNotFoundError: print(f"Error: Model/scaler not found. Run 'train' mode first."); return
    except Exception as e: print(f"Error loading model/scaler: {e}"); return
    try:
        conn_test = sqlite3.connect(db_file); cursor_test = conn_test.cursor()
        cursor_test.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='alerts';")
        if not cursor_test.fetchone(): print("Alerts table not found, running full DB setup..."); conn_test.close(); setup_database(db_file)
        else: conn_test.close()
        log_dir = os.path.dirname(alert_log_file)
        if log_dir and not os.path.exists(log_dir): os.makedirs(log_dir); print(f"Created log directory: {log_dir}")
    except sqlite3.Error as e: print(f"\nDB setup failed for {db_file}: {e}. Aborting detection."); return
    except OSError as e: print(f"Error setting up log dir {log_dir}: {e}"); return

    print(f"\nStarting DNS Anomaly Detection Agent on interface {interface}...")
    print("Press Ctrl+C to stop.")
    try:
        callback = lambda pkt: process_packet_detect(pkt, model, scaler, alert_log_file, db_file)
        sniff(iface=interface, filter="udp port 53", prn=callback, store=0)
    except PermissionError: print(f"\nError: Need root privileges to sniff on {interface}.\nTry 'sudo'.")
    except Exception as e: print(f"\nAn error occurred during detection sniffing: {e}")
    finally: print("\n--- Stopping Detection Agent ---")

def run_collection(interface, db_file, label_value):
    """Runs the data collection mode, labeling data with the specified label."""
    print(f"--- Starting Data Collection Mode ---")
    print(f"Interface: {interface}")
    print(f"Using database file: {db_file} (for features)")
    print(f"Labeling collected data as: {label_value} ({'Normal' if label_value == 0 else 'Attack'})")
    try:
        setup_database(db_file) # Creates tables if they don't exist
        print(f"\nStarting DNS traffic capture on interface {interface}...")
        print("Press Ctrl+C to stop.")
        # Pass the correct process_packet_collect
        callback = lambda pkt: process_packet_collect(pkt, db_file, label_value)
        sniff(iface=interface, filter="udp port 53", prn=callback, store=0)
    except PermissionError:
        print(f"\nError: Need root/administrator privileges to sniff on {interface}.\nTry running with 'sudo'.")
    except sqlite3.Error as e:
        print(f"\nDatabase setup failed for {db_file}: {e}. Aborting.")
    except Exception as e:
        print(f"\nAn error occurred during sniffing: {e}")
    finally:
        print("\n--- Stopping Data Collection ---")

# Main 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="DNS Anomaly Detection Agent")
    parser.add_argument( "--mode", required=True, choices=['collect', 'train', 'detect'] )
    parser.add_argument( "--interface", "-i", default=DEFAULT_INTERFACE )
    parser.add_argument( "--db-file", default=DEFAULT_DB_FILE )
    parser.add_argument( "--model", default=DEFAULT_MODEL_FILE )
    parser.add_argument( "--scaler", default=DEFAULT_SCALER_FILE )
    parser.add_argument( "--log-file", default=DEFAULT_ALERT_LOG_FILE )
    parser.add_argument( "--test-split", type=float, default=DEFAULT_TEST_SPLIT )
    parser.add_argument( "--label", type=int, default=0, choices=[0, 1] )
    parser.add_argument( "--contamination", type=float, default=0.3, help="Contamination factor for Isolation Forest (train mode)." )

    args = parser.parse_args() # Define args globally

    if not (0.0 <= args.test_split < 1.0): print("Error: --test-split invalid."); sys.exit(1)
    if not (0.0 < args.contamination <= 0.5): print("Warning: Contamination should be > 0 and <= 0.5.")

    if args.mode == 'collect': run_collection(args.interface, args.db_file, args.label)
    elif args.mode == 'train': run_training(args.db_file, args.model, args.scaler, args.test_split)
    elif args.mode == 'detect': run_detection(args.interface, args.model, args.scaler, args.log_file, args.db_file)
    else: print(f"Error: Invalid mode '{args.mode}'."); parser.print_help(); sys.exit(1)