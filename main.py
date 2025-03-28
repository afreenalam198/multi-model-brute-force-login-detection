import random
import pandas as pd
import numpy as np
import os
import joblib
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.model_selection import train_test_split
from sklearn.ensemble import IsolationForest
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, roc_curve
from tensorflow.keras.models import Sequential
from tensorflow.keras.layers import LSTM, Dense
from datetime import datetime, timedelta
from faker import Faker

class AnomalyDetector:
    def __init__(self, data_path, model_path, contamination=0.01, random_state=42, seq_length=10):
        self.data_path = data_path
        self.model_path = model_path
        self.contamination = contamination
        self.random_state = random_state
        self.seq_length = seq_length
        
        # Ensure model and data paths exist
        os.makedirs(model_path, exist_ok=True)
        os.makedirs(data_path, exist_ok=True)

    def generate_logs(self):
        """
        Generate synthetic login logs with benign and attack scenarios
        Maintains temporal order during train-test split
        """
        #from log_generators import generate_benign_logins, generate_brute_force_attacks

        # Generate logs
        #benign_logs = generate_benign_logins()
        #brute_force_logs = generate_brute_force_attacks()

        from log_import import import_benign_logs, import_brute_force_attack_logs

        # Generate logs
        benign_logs = import_benign_logs()
        brute_force_logs = import_brute_force_attack_logs()

        # Convert to DataFrames and sort by timestamp
        benign_df = pd.DataFrame(benign_logs, columns=["timestamp", "username", "location", "ip_address", "port", "protocol", "login_status"])
        attack_df = pd.DataFrame(brute_force_logs, columns=["timestamp", "username", "location", "ip_address", "port", "protocol", "login_status"])
        
        # Sort both DataFrames by timestamp
        benign_df = benign_df.sort_values("timestamp").reset_index(drop=True)
        attack_df = attack_df.sort_values("timestamp").reset_index(drop=True)

        # Split by temporal order instead of random shuffling
        benign_train_end = int(len(benign_df) * 0.8)
        attack_train_end = int(len(attack_df) * 0.8)

        benign_train = benign_df[:benign_train_end]
        benign_test = benign_df[benign_train_end:]
        attack_train = attack_df[:attack_train_end]
        attack_test = attack_df[attack_train_end:]

        # Combine train and test sets, maintaining original timestamp order
        train_df = pd.concat([benign_train, attack_train]).sort_values("timestamp").reset_index(drop=True)
        test_df = pd.concat([benign_test, attack_test]).sort_values("timestamp").reset_index(drop=True)

        # Save datasets
        train_df.to_csv(os.path.join(self.data_path, 'train_logs.csv'), index=False)
        test_df.to_csv(os.path.join(self.data_path, 'test_logs.csv'), index=False)

        return train_df, test_df

    def preprocess_ip_data(self, df):
        """
        Preprocess IP-based features
        """
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['port'] = pd.to_numeric(df['port'])

        ip_based_df = df.groupby('ip_address').agg(
            failed_attempts=('login_status', lambda x: (x == 'failure').sum()),
            successful_attempts=('login_status', lambda x: (x == 'success').sum())
        ).reset_index()

        # Data Scaling
        numerical_features = ['failed_attempts', 'successful_attempts']
        scaler = StandardScaler()
        ip_based_df[numerical_features] = scaler.fit_transform(ip_based_df[numerical_features])

        return ip_based_df, numerical_features, scaler

    def preprocess_time_data(self, df, time_window='30s'):
        """
        Preprocess time series features
        """
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df['port'] = pd.to_numeric(df['port'])

        time_series_df = df.groupby(pd.Grouper(key='timestamp', freq=time_window)).agg(
            failed_attempts=('login_status', lambda x: (x == 'failure').sum()),
            unique_ips=('ip_address', 'nunique'),
            unique_usernames=('username', 'nunique'),
            unique_ports=('port', 'nunique'),
            http_fails=('protocol', lambda x: ((x == 'HTTP') & (df['login_status'] == 'failure')).sum()),
            https_fails=('protocol', lambda x: ((x == 'HTTPS') & (df['login_status'] == 'failure')).sum()),
            ftp_fails=('protocol', lambda x: ((x == 'FTP') & (df['login_status'] == 'failure')).sum()),
            ssh_fails=('protocol', lambda x: ((x == 'SSH') & (df['login_status'] == 'failure')).sum())
        ).reset_index()

        # Feature Engineering
        time_series_df['failed_attempts_rate'] = time_series_df['failed_attempts'] / pd.Timedelta(time_window).total_seconds()

        # Data Scaling
        numerical_features = ['failed_attempts', 'unique_ips', 'unique_usernames', 'unique_ports', 
                              'failed_attempts_rate', 'http_fails', 'https_fails', 'ftp_fails', 'ssh_fails']
        time_series_df[numerical_features] = time_series_df[numerical_features].apply(pd.to_numeric)

        scaler = StandardScaler()
        time_series_df[numerical_features] = scaler.fit_transform(time_series_df[numerical_features])

        # Handle NaN values
        time_series_df = time_series_df.fillna(0)

        return time_series_df, numerical_features, scaler

    def create_lstm_sequences(self, data, seq_length):
        """
        Create sequences for LSTM model
        """
        xs, ys = [], []
        for i in range(len(data) - seq_length):
            x = data[i:i + seq_length]
            y = data[i + seq_length]
            xs.append(x)
            ys.append(y)
        return np.array(xs), np.array(ys)

    def prepare_lstm_data(self, time_series_df, numerical_features, seq_length):
        """
        Prepare data for LSTM model
        """
        # Scale all numerical features using MinMaxScaler
        scaler = MinMaxScaler()
        scaled_data = scaler.fit_transform(time_series_df[numerical_features])

        X, y = self.create_lstm_sequences(scaled_data, seq_length)
        X = np.reshape(X, (X.shape[0], X.shape[1], X.shape[2]))
        
        # Split into Train and Validation
        X_train, X_val, y_train, y_val = train_test_split(X, y, test_size=0.2, shuffle=False)

        return X_train, X_val, y_train, y_val, scaled_data, scaler

    def train_ip_isolation_forest(self, train_df):
        """
        Train IP-based Isolation Forest model
        """
        ip_based_df, numerical_features, scaler = self.preprocess_ip_data(train_df)
        
        model = IsolationForest(
            contamination=self.contamination, 
            random_state=self.random_state
        )
        model.fit(ip_based_df[numerical_features])
        
        # Save model and scaler
        joblib.dump(model, os.path.join(self.model_path, 'ip_isolation_forest.joblib'))
        joblib.dump(scaler, os.path.join(self.model_path, 'ip_scaler.joblib'))
        
        return model, ip_based_df, numerical_features, scaler

    def train_time_isolation_forest(self, train_df):
        """
        Train Time-Series Isolation Forest model
        """
        time_series_df, numerical_features, scaler = self.preprocess_time_data(train_df)
        
        model = IsolationForest(
            contamination=self.contamination, 
            random_state=self.random_state
        )
        model.fit(time_series_df[numerical_features])
        
        # Save model and scaler
        joblib.dump(model, os.path.join(self.model_path, 'time_isolation_forest.joblib'))
        joblib.dump(scaler, os.path.join(self.model_path, 'time_scaler.joblib'))
        
        return model, time_series_df, numerical_features, scaler

    def train_lstm_model(self, train_df, numerical_features, epochs=10):
        """
        Train LSTM model
        """
        time_series_df, features, time_scaler = self.preprocess_time_data(train_df)
        
        X_train, X_val, y_train, y_val, scaled_data, data_scaler = self.prepare_lstm_data(
            time_series_df, 
            numerical_features, 
            self.seq_length
        )

        model = Sequential([
            LSTM(50, activation='relu', input_shape=(X_train.shape[1], X_train.shape[2])),
            Dense(X_train.shape[2])
        ])
        model.compile(optimizer='adam', loss='mse')
        model.fit(X_train, y_train, epochs=epochs, validation_data=(X_val, y_val), verbose=1)
        
        # Save model and scalers
        model.save(os.path.join(self.model_path, 'lstm_model.h5'))
        joblib.dump(data_scaler, os.path.join(self.model_path, 'lstm_data_scaler.joblib'))
        joblib.dump(time_scaler, os.path.join(self.model_path, 'lstm_time_scaler.joblib'))
        
        return model, scaled_data, data_scaler

    def calculate_lstm_anomaly_scores(self, model, scaled_data, seq_length):
        """
        Calculate anomaly scores for LSTM model
        """
        X, _ = self.create_lstm_sequences(scaled_data, seq_length)
        X = np.reshape(X, (X.shape[0], X.shape[1], X.shape[2]))

        y_pred = model.predict(X)
        mse = np.mean(np.power(scaled_data[seq_length:] - y_pred, 2), axis=1)

        lstm_anomaly_scores = np.concatenate(([0] * seq_length, mse))
        return lstm_anomaly_scores

    def classify_anomalies(self, scores, threshold_percentile=95):
        """
        Classify anomalies based on threshold
        """
        threshold = np.percentile(scores, threshold_percentile)
        anomaly_labels = np.where(scores > threshold, -1, 1)
        return anomaly_labels

    def evaluate_models(self, test_df, ip_based_df, time_series_df):
        """
        Evaluate models and generate visualizations
        """
        # Prepare true labels for time series
        y_true_time = np.where(time_series_df['failed_attempts'] > 0, -1, 1)

        # Prepare true labels for IP-based detection
        ip_failure_counts = test_df.groupby('ip_address')['login_status'].agg(
            lambda x: (x == 'failure').sum()
        ).reset_index()
        
        ip_based_df_with_labels = ip_based_df.merge(
            ip_failure_counts, 
            left_on='ip_address', 
            right_on='ip_address', 
            how='left'
        )
        
        y_true_ip = np.where(
            ip_based_df_with_labels['login_status'].fillna(0) > 0, 
            -1, 
            1
        )

        models = {
            'IP-based Isolation Forest': (
                ip_based_df['ip_isolation_forest_anomaly_label'], 
                y_true_ip
            ),
            'Time-Series Isolation Forest': (
                time_series_df['time_isolation_forest_anomaly_label'], 
                y_true_time
            ),
            'LSTM': (
                time_series_df['lstm_anomaly_label'], 
                y_true_time
            )
        }

        for model_name, (predictions, true_labels) in models.items():
            print(f"\n{model_name} Classification Report:")
            
            # Ensure predictions and true labels have consistent length
            if len(predictions) != len(true_labels):
                # Truncate to the shorter length
                min_length = min(len(predictions), len(true_labels))
                predictions = predictions[:min_length]
                true_labels = true_labels[:min_length]
            
            print(classification_report(
                true_labels, 
                predictions, 
                zero_division=1,  # Set to 1 to avoid warnings
                target_names=['Anomaly', 'Normal']  
            ))
            
            # Determine which DataFrame to use for visualization
            if model_name == 'IP-based Isolation Forest':
                viz_df = ip_based_df
                label_col = 'ip_isolation_forest_anomaly_label'
            elif model_name == 'Time-Series Isolation Forest':
                viz_df = time_series_df
                label_col = 'time_isolation_forest_anomaly_label'
            else:  # LSTM
                viz_df = time_series_df
                label_col = 'lstm_anomaly_label'
            
            self._visualize_anomalies(
                model_name, 
                viz_df, 
                true_labels, 
                predictions, 
                label_col
            )

            # Additional diagnostic information
            print(f"\nModel: {model_name}")
            print(f"Predictions shape: {predictions.shape}")
            print(f"True labels shape: {true_labels.shape}")
            print("Anomaly distribution:")
            unique, counts = np.unique(predictions, return_counts=True)
            for u, c in zip(unique, counts):
                print(f"  {u}: {c}")

    def _visualize_anomalies(self, model_name, df, true_val, predictions, anomaly_label):
        """
        Generate visualization for anomaly detection results
        """
        # Confusion Matrix
        plt.figure(figsize=(8, 6))
        cm = confusion_matrix(true_val, predictions)
        sns.heatmap(cm, annot=True, fmt='d', cmap='Blues')
        plt.title(f'{model_name} Confusion Matrix')
        plt.xlabel('Predicted')
        plt.ylabel('True')
        plt.tight_layout()
        plt.savefig(os.path.join(self.model_path, f'{model_name}_confusion_matrix.png'))
        plt.close()

        # Anomaly Distribution Chart
        plt.figure(figsize=(8, 6))
        temp_df = pd.DataFrame({anomaly_label: predictions})
        sns.countplot(x=anomaly_label, data=df, hue=anomaly_label, palette=['skyblue', 'salmon'], legend=False)
        plt.title(f'Anomaly Distribution - {model_name}')
        plt.xlabel('Anomaly (1 = Normal, -1 = Anomaly)')
        plt.ylabel('Count')
        plt.tight_layout()
        plt.savefig(os.path.join(self.model_path, f'{model_name}_anomaly_distribution.png'))
        plt.close()

        # ROC-AUC Curve
        y_true_binary = np.where(true_val == -1, 1, 0)
        y_pred_proba = np.where(predictions == -1, 1, 0)

        fpr, tpr, thresholds = roc_curve(y_true_binary, y_pred_proba)
        roc_auc = roc_auc_score(y_true_binary, y_pred_proba)

        plt.figure(figsize=(8, 6))
        plt.plot(fpr, tpr, color='darkorange', lw=2, 
                label=f'ROC curve (AUC = {roc_auc:.2f})')
        plt.plot([0, 1], [0, 1], color='navy', lw=2, linestyle='--')
        plt.xlim([0.0, 1.0])
        plt.ylim([0.0, 1.05])
        plt.xlabel('False Positive Rate')
        plt.ylabel('True Positive Rate')
        plt.title(f'Receiver Operating Characteristic - {model_name}')
        plt.legend(loc="lower right")
        plt.tight_layout()
        plt.savefig(os.path.join(self.model_path, f'{model_name}_roc_curve.png'))
        plt.close()

    def run_anomaly_detection(self):
        """
        Main method to run the entire anomaly detection pipeline
        """
        # Generate logs with train and test split
        train_df, test_df = self.generate_logs()

        # Train models
        ip_model, ip_based_df, ip_features, ip_scaler = self.train_ip_isolation_forest(train_df)
        time_model, time_series_df, time_features, time_scaler = self.train_time_isolation_forest(train_df)
        lstm_model, scaled_data_lstm, lstm_scaler = self.train_lstm_model(train_df, time_features)

        # Predict anomalies
        ip_based_df['ip_isolation_forest_anomaly_label'] = ip_model.predict(ip_based_df[ip_features])
        time_series_df['time_isolation_forest_anomaly_label'] = time_model.predict(time_series_df[time_features])
        
        # LSTM anomaly detection
        lstm_anomaly_scores = self.calculate_lstm_anomaly_scores(lstm_model, scaled_data_lstm, self.seq_length)
        time_series_df['lstm_anomaly_score'] = lstm_anomaly_scores
        time_series_df['lstm_anomaly_label'] = self.classify_anomalies(lstm_anomaly_scores)

        # Evaluate models
        self.evaluate_models(test_df, ip_based_df, time_series_df)

def main():
    detector = AnomalyDetector(
        data_path='.venv/brute-force-detection/data',
        model_path='.venv/brute-force-detection/models',
        contamination=0.01,
        random_state=42,
        seq_length=10
    )
    detector.run_anomaly_detection()

if __name__ == "__main__":
    main()