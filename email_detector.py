#!/usr/bin/env python
# coding: utf-8

# # Email Detector
# 
# This notebook demonstrates a sound approach to detect disposable and suspicious email domains.

# In[ ]:


import os
import re
import pickle
import json
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler, MinMaxScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, roc_auc_score
from sklearn.calibration import CalibratedClassifierCV
from sklearn.utils.class_weight import compute_class_weight
from sklearn.feature_selection import SelectKBest, mutual_info_classif
import dns.resolver
import whois
import logging
from datetime import datetime
import difflib
import ssl
import socket
import warnings
import urllib.parse
from tqdm import tqdm
from scipy import stats
import math
import csv
from pathlib import Path
warnings.filterwarnings('ignore')

class EmailDetector:
    """
    A ly sound email detector with proper feature engineering,
    balanced training, and unbiased predictions.
    """

    def __init__(self, config_path="email_detector_config.json"):
        """Initialize the detector with  foundations."""
        self.model = None
        self.feature_cache = {}
        self.dns_cache = {}

        # Set up logging
        logging.basicConfig(
            level=logging.INFO,
            format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        )
        self.logger = logging.getLogger(__name__)

        # Load configuration
        self.config = self._load_config(config_path)

        # File paths
        self.allow_list_path = self.config.get('allow_list_path', '/input/legitimate_emails.txt')
        self.deny_list_path = self.config.get('deny_list_path', '/input/disposable_emails.txt')
        self.model_path = self.config.get('model_path', '/models/ikick_email_detector_api.pkl')
        
        # Path for suspected disposable domains CSV
        self.suspected_disposable_path = self.config.get('suspected_disposable_path', 'suspected_disposable_domains.csv')
        self.suspected_domains_threshold = self.config.get('suspected_domains_threshold', 0.55)  # 85% confidence

        # Load domain lists
        self.legitimate_domains = self._load_domain_list(self.allow_list_path)
        self.disposable_domains = self._load_domain_list(self.deny_list_path)
        
        # Load previously identified suspected disposable domains
        self.suspected_disposable_domains = self._load_suspected_domains()

        #  parameters
        self.feature_importance_threshold = 0.01  # 1% minimum importance
        self.confidence_calibration_factor = 1.5
        self.class_balance_ratio = 1.0  # Equal weight for both classes

        # Model configuration
        self.model_config = None
        self.feature_scaler = None
        self.feature_selector = None
        self.calibrated_model = None

        # Feature engineering patterns
        self.disposable_patterns = {
            'keywords': ['temp', 'disposable', 'throwaway', 'guerrilla', 'mailinator'],
            'patterns': [r'\d{3,}$', r'temp\d+', r'test\d+']
        }

        self.legitimate_patterns = {
            'tlds': ['.com', '.org', '.net', '.edu', '.gov'],
            'patterns': [r'^[a-z]+\.[a-z]+$', r'^mail\.[a-z]+\.[a-z]+$']
        }

   #configurations
    def _load_config(self, config_path):
        """Load configuration from JSON file."""
        default_config = {
            'use_dns': True,
            'use_whois': True, 
            'max_features': 30,
            'cv_folds': 5,
            'random_state': 42,
            'suspected_disposable_path': '/output/suspected_disposable_domains.csv',
            'suspected_domains_threshold': 0.85
        }

        if config_path and os.path.exists(config_path):
            try:
                with open(config_path, 'r') as f:
                    config = json.load(f)
                default_config.update(config)
            except Exception as e:
                self.logger.error(f"Error loading config: {str(e)}")

        return default_config

    def _load_domain_list(self, file_path):
        """Load domain list from file."""
        domains = set()
        if os.path.exists(file_path):
            try:
                with open(file_path, 'r') as f:
                    for line in f:
                        line = line.strip().lower()
                        if line and not line.startswith('#'):
                            domains.add(line)
            except Exception as e:
                self.logger.warning(f"Error loading {file_path}: {str(e)}")
        return domains

    def _load_suspected_domains(self):
        """Load previously identified suspected disposable domains from CSV."""
        suspected_domains = set()
        if os.path.exists(self.suspected_disposable_path):
            try:
                df = pd.read_csv(self.suspected_disposable_path)
                suspected_domains = set(df['domain'].str.lower())
            except Exception as e:
                self.logger.warning(f"Error loading suspected domains: {str(e)}")
        return suspected_domains

    def _save_suspected_domain(self, domain, confidence, reasons):
        """Save a newly suspected disposable domain to CSV."""
        # Create the CSV file if it doesn't exist
        if not os.path.exists(self.suspected_disposable_path):
            with open(self.suspected_disposable_path, 'w', newline='') as f:
                writer = csv.writer(f)
                writer.writerow(['domain', 'confidence', 'timestamp', 'reasons', 'top_features'])
        
        # Check if domain already exists in the CSV
        if os.path.exists(self.suspected_disposable_path):
            df = pd.read_csv(self.suspected_disposable_path)
            if domain.lower() in df['domain'].str.lower().values:
                return  
        
        # Prepare reasons string
        reasons_str = '; '.join(reasons)
        
        # Save to CSV
        with open(self.suspected_disposable_path, 'a', newline='') as f:
            writer = csv.writer(f)
            writer.writerow([
                domain,
                f"{confidence:.3f}",
                datetime.now().isoformat(),
                reasons_str,
                json.dumps([f['feature'] for f in self.last_top_features[:3]])  # Store top 3 feature names
            ])
        
        # Add to in-memory set
        self.suspected_disposable_domains.add(domain.lower())
        
        self.logger.info(f"Saved suspected disposable domain: {domain} (confidence: {confidence:.3f})")

    def load_emails_from_file(self, file_path):
        """Load emails from a text file (one email per line)."""
        emails = []
        
        if not os.path.exists(file_path):
            self.logger.error(f"Email file not found: {file_path}")
            return emails
        
        try:
            with open(file_path, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    # Skip empty lines and comments
                    if line and not line.startswith('#'):
                        emails.append(line)
            
            self.logger.info(f"Loaded {len(emails)} emails from {file_path}")
        except Exception as e:
            self.logger.error(f"Error loading emails from file: {str(e)}")
        
        return emails

    def check_emails_from_file(self, file_path, output_csv=None, output_json=None):
        """Check emails from a text file and optionally save results."""
        print(f"\nProcessing emails from: {file_path}")
        print("="*50)
        
        # Load emails
        emails = self.load_emails_from_file(file_path)
        
        if not emails:
            print("No emails found in file.")
            return []
        
        print(f"Found {len(emails)} emails to check")
        
        # Process emails
        results = self.predict(emails)
        
        # Display summary
        disposable_count = sum(1 for r in results if r['is_disposable'])
        legitimate_count = len(results) - disposable_count
        
        print(f"\nSummary:")
        print(f"- Total emails: {len(results)}")
        print(f"- Disposable: {disposable_count} ({disposable_count/len(results)*100:.1f}%)")
        print(f"- Legitimate: {legitimate_count} ({legitimate_count/len(results)*100:.1f}%)")
        
        # Save results if output paths specified
        if output_csv:
            self._save_results_to_csv(results, output_csv)
            print(f"\nResults saved to CSV: {output_csv}")
        
        if output_json:
            self._save_results_to_json(results, output_json)
            print(f"Results saved to JSON: {output_json}")
        
        return results

    def _save_results_to_csv(self, results, output_path):
        """Save prediction results to CSV file."""
        # Prepare data for CSV
        csv_data = []
        for result in results:
            csv_data.append({
                'email': result['input'],
                'domain': result['domain'],
                'is_disposable': result['is_disposable'],
                'confidence': result['confidence'],
                'probability_legitimate': result['probability_legitimate'],
                'probability_disposable': result['probability_disposable'],
                'in_training_legitimate': result['in_training_legitimate'],
                'in_training_disposable': result['in_training_disposable'],
                'in_suspected_disposable': result['in_suspected_disposable'],
                'top_feature_1': result['top_features'][0]['feature'] if result['top_features'] else '',
                'top_feature_1_value': result['top_features'][0]['value'] if result['top_features'] else '',
                'top_feature_2': result['top_features'][1]['feature'] if len(result['top_features']) > 1 else '',
                'top_feature_2_value': result['top_features'][1]['value'] if len(result['top_features']) > 1 else '',
            })
        
        # Save to CSV
        df = pd.DataFrame(csv_data)
        df.to_csv(output_path, index=False)

    def _save_results_to_json(self, results, output_path):
        """Save prediction results to JSON file."""
        with open(output_path, 'w') as f:
            json.dump(results, f, indent=2)

    def extract_domain(self, email_or_domain):
        """Extract domain from email."""
        if not email_or_domain:
            return ""
        email_or_domain = str(email_or_domain).strip().lower()
        if '@' in email_or_domain:
            return email_or_domain.split('@')[-1]
        return email_or_domain

    def extract_features(self, email_or_domain):
        """Extract features using  techniques."""
        domain = self.extract_domain(email_or_domain)

        # Check cache first
        cache_key = f"features_{domain}"
        if cache_key in self.feature_cache:
            return self.feature_cache[cache_key]

        features = {}

        # 1. Domain structure features
        features.update(self._extract_structure_features(domain))

        # 2. Statistical features
        features.update(self._extract_statistical_features(domain))

        # 3. Pattern matching features
        features.update(self._extract_pattern_features(domain))

        # 4. DNS features (if enabled)
        if self.config.get('use_dns', True):
            features.update(self._extract_dns_features(domain))

        # 5. Similarity features
        features.update(self._extract_similarity_features(domain))

        # 6. List membership (encoded properly)
        features['in_disposable_list'] = 1.0 if domain in self.disposable_domains else 0.0
        features['in_legitimate_list'] = 1.0 if domain in self.legitimate_domains else 0.0
        
        # NEW: Add feature for suspected domains
        features['in_suspected_list'] = 1.0 if domain in self.suspected_disposable_domains else 0.0

        # Cache the features
        self.feature_cache[cache_key] = features
        return features

    def _extract_structure_features(self, domain):
        """Extract structural features from domain."""
        features = {}

        # Basic structure
        parts = domain.split('.')
        features['domain_length'] = len(domain)
        features['subdomain_count'] = len(parts) - 2 if len(parts) > 2 else 0
        features['tld_length'] = len(parts[-1]) if parts else 0

        # Character composition
        features['digit_ratio'] = sum(c.isdigit() for c in domain) / len(domain) if domain else 0
        features['alpha_ratio'] = sum(c.isalpha() for c in domain) / len(domain) if domain else 0
        features['special_char_ratio'] = sum(not c.isalnum() and c != '.' for c in domain) / len(domain) if domain else 0

        # Entropy (randomness measure)
        features['domain_entropy'] = self._calculate_entropy(domain)

        return features

    def _extract_statistical_features(self, domain):
        """Extract statistical features."""
        features = {}

        # Character distribution
        char_counts = {}
        for char in domain:
            char_counts[char] = char_counts.get(char, 0) + 1

        # Statistical measures
        counts = list(char_counts.values())
        features['char_mean_frequency'] = np.mean(counts) if counts else 0
        features['char_std_frequency'] = np.std(counts) if counts else 0
        features['char_unique_ratio'] = len(char_counts) / len(domain) if domain else 0

        # Vowel/consonant ratio
        vowels = set('aeiouAEIOU')
        vowel_count = sum(1 for c in domain if c in vowels)
        consonant_count = sum(1 for c in domain if c.isalpha() and c not in vowels)
        features['vowel_consonant_ratio'] = vowel_count / (consonant_count + 1)

        # Sequential patterns
        features['max_char_sequence'] = self._max_char_sequence(domain)
        features['digit_sequences'] = len(re.findall(r'\d+', domain))

        return features

    def _extract_pattern_features(self, domain):
        """Extract pattern-based features."""
        features = {}

        # Disposable patterns
        disposable_score = 0
        for keyword in self.disposable_patterns['keywords']:
            if keyword in domain:
                disposable_score += 1
        for pattern in self.disposable_patterns['patterns']:
            if re.search(pattern, domain):
                disposable_score += 1
        features['disposable_pattern_score'] = disposable_score

        # Legitimate patterns
        legitimate_score = 0
        for tld in self.legitimate_patterns['tlds']:
            if domain.endswith(tld):
                legitimate_score += 1
        for pattern in self.legitimate_patterns['patterns']:
            if re.match(pattern, domain):
                legitimate_score += 1
        features['legitimate_pattern_score'] = legitimate_score

        # Specific patterns
        features['has_numbers'] = float(bool(re.search(r'\d', domain)))
        features['starts_with_digit'] = float(domain[0].isdigit() if domain else False)
        features['has_hyphen'] = float('-' in domain)
        features['multiple_dots'] = float(domain.count('.') > 1)

        return features

    def _extract_dns_features(self, domain):
        """Extract DNS-based features."""
        features = {
            'has_mx_record': 0.0,
            'has_a_record': 0.0,
            'mx_count': 0,
            'a_count': 0
        }

        try:
            # Check MX records
            mx_records = dns.resolver.resolve(domain, 'MX', lifetime=2)
            features['has_mx_record'] = 1.0
            features['mx_count'] = len(mx_records)
        except:
            pass

        try:
            # Check A records
            a_records = dns.resolver.resolve(domain, 'A', lifetime=2)
            features['has_a_record'] = 1.0
            features['a_count'] = len(a_records)
        except:
            pass

        return features

    def _extract_similarity_features(self, domain):
        """Extract similarity features using  distance metrics."""
        features = {}

        # Sample domains for comparison
        legitimate_sample = list(self.legitimate_domains)[:50]
        disposable_sample = list(self.disposable_domains)[:50]

        # Calculate similarities
        if legitimate_sample:
            similarities = [self._calculate_similarity(domain, ref) for ref in legitimate_sample]
            features['max_legitimate_similarity'] = max(similarities)
            features['avg_legitimate_similarity'] = np.mean(similarities)
            features['std_legitimate_similarity'] = np.std(similarities)
        else:
            features['max_legitimate_similarity'] = 0
            features['avg_legitimate_similarity'] = 0
            features['std_legitimate_similarity'] = 0

        if disposable_sample:
            similarities = [self._calculate_similarity(domain, ref) for ref in disposable_sample]
            features['max_disposable_similarity'] = max(similarities)
            features['avg_disposable_similarity'] = np.mean(similarities)
        else:
            features['max_disposable_similarity'] = 0
            features['avg_disposable_similarity'] = 0

        # Relative similarity score
        features['similarity_differential'] = (
            features['avg_legitimate_similarity'] - features['avg_disposable_similarity']
        )

        return features

    def _calculate_entropy(self, text):
        """Calculate Shannon entropy of text."""
        if not text:
            return 0

        # Character frequency distribution
        char_freq = {}
        for char in text:
            char_freq[char] = char_freq.get(char, 0) + 1

        # Calculate entropy
        entropy = 0
        for count in char_freq.values():
            probability = count / len(text)
            if probability > 0:
                entropy -= probability * math.log2(probability)

        return entropy

    def _max_char_sequence(self, text):
        """Find maximum consecutive character sequence."""
        if not text:
            return 0

        max_seq = 1
        current_seq = 1

        for i in range(1, len(text)):
            if text[i] == text[i-1]:
                current_seq += 1
                max_seq = max(max_seq, current_seq)
            else:
                current_seq = 1

        return max_seq

    def _calculate_similarity(self, domain1, domain2):
        """Calculate similarity using multiple metrics."""
        # Levenshtein distance (normalized)
        levenshtein = difflib.SequenceMatcher(None, domain1, domain2).ratio()

        # Jaccard similarity (character-level)
        set1 = set(domain1)
        set2 = set(domain2)
        jaccard = len(set1.intersection(set2)) / len(set1.union(set2)) if set1.union(set2) else 0

        # Combined similarity
        return (levenshtein + jaccard) / 2

    def train(self, force_retrain=False):
        """Train the model with proper  foundations."""
        print("="*70)
        print("TRAINING  EMAIL DETECTOR")
        print("="*70)

        # Check if model exists and not forcing retrain
        if not force_retrain and os.path.exists(self.model_path):
            print("Model already exists. Use force_retrain=True to retrain.")
            return self.load_model()

        # Prepare balanced training data
        print("\n1. Preparing balanced training data...")
        X, y = self._prepare_training_data()

        # Feature scaling
        print("\n2. Scaling features...")
        self.feature_scaler = StandardScaler()
        X_scaled = self.feature_scaler.fit_transform(X)

        # Feature selection
        print("\n3. Selecting best features...")
        self.feature_selector = SelectKBest(
            score_func=mutual_info_classif,
            k=min(self.config.get('max_features', 30), X.shape[1])
        )
        X_selected = self.feature_selector.fit_transform(X_scaled, y)

        # Get selected feature names
        selected_indices = self.feature_selector.get_support(indices=True)
        selected_features = [X.columns[i] for i in selected_indices]
        print(f"Selected {len(selected_features)} features")

        # Class weights for balanced training
        class_weights = compute_class_weight(
            'balanced',
            classes=np.unique(y),
            y=y
        )
        class_weight_dict = dict(zip(np.unique(y), class_weights))

        # Train ensemble model
        print("\n4. Training ensemble model...")
        base_model = self._create_ensemble_model(class_weight_dict)

        # Cross-validation
        cv = StratifiedKFold(n_splits=self.config.get('cv_folds', 5), shuffle=True, random_state=42)
        scores = cross_val_score(base_model, X_selected, y, cv=cv, scoring='roc_auc')
        print(f"Cross-validation AUC: {scores.mean():.3f} (+/- {scores.std() * 2:.3f})")

        # Train final model
        base_model.fit(X_selected, y)

        # Calibrate probabilities
        print("\n5. Calibrating probabilities...")
        self.calibrated_model = CalibratedClassifierCV(
            base_model,
            method='sigmoid',
            cv=3
        )
        self.calibrated_model.fit(X_selected, y)

        # Evaluate on test set
        print("\n6. Evaluating model...")
        X_train, X_test, y_train, y_test = train_test_split(
            X_selected, y, test_size=0.2, stratify=y, random_state=42
        )

        y_pred = self.calibrated_model.predict(X_test)
        y_proba = self.calibrated_model.predict_proba(X_test)[:, 1]

        print(f"Test Accuracy: {accuracy_score(y_test, y_pred):.3f}")
        print(f"Test Precision: {precision_score(y_test, y_pred):.3f}")
        print(f"Test Recall: {recall_score(y_test, y_pred):.3f}")
        print(f"Test F1: {f1_score(y_test, y_pred):.3f}")
        print(f"Test AUC: {roc_auc_score(y_test, y_proba):.3f}")

        # Store model configuration
        self.model_config = {
            'feature_names': list(X.columns),
            'selected_features': selected_features,
            'feature_scaler': self.feature_scaler,
            'feature_selector': self.feature_selector,
            'training_date': datetime.now().isoformat(),
            'n_samples': len(X),
            'n_features': len(selected_features),
            'class_balance': dict(zip(*np.unique(y, return_counts=True)))
        }

        # Save model
        self.save_model()
        print("\n7. Model saved successfully!")

        return True

    def _prepare_training_data(self):
        """Prepare balanced training data."""
        features_list = []
        labels = []

        # Extract features for legitimate domains
        for domain in tqdm(self.legitimate_domains, desc="Processing legitimate domains"):
            features = self.extract_features(domain)
            features_list.append(features)
            labels.append(0)

        # Extract features for disposable domains
        for domain in tqdm(self.disposable_domains, desc="Processing disposable domains"):
            features = self.extract_features(domain)
            features_list.append(features)
            labels.append(1)

        # Convert to DataFrame
        X = pd.DataFrame(features_list)
        y = np.array(labels)

        # Balance the dataset if needed
        unique, counts = np.unique(y, return_counts=True)
        print(f"\nClass distribution: {dict(zip(unique, counts))}")

        # If imbalanced, undersample the majority class
        if counts[0] != counts[1]:
            min_count = min(counts)
            balanced_indices = []

            for label in unique:
                label_indices = np.where(y == label)[0]
                sampled_indices = np.random.choice(label_indices, min_count, replace=False)
                balanced_indices.extend(sampled_indices)

            np.random.shuffle(balanced_indices)
            X = X.iloc[balanced_indices]
            y = y[balanced_indices]

            print(f"Balanced to {min_count} samples per class")

        return X, y

    def _create_ensemble_model(self, class_weights):
        """Create ensemble model with proper configuration."""
        # Use a calibrated ensemble
        rf = RandomForestClassifier(
            n_estimators=100,
            max_depth=10,
            min_samples_split=5,
            class_weight=class_weights,
            random_state=42
        )

        gb = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=5,
            learning_rate=0.1,
            random_state=42
        )

        lr = LogisticRegression(
            class_weight=class_weights,
            max_iter=1000,
            random_state=42
        )

        # Voting classifier
        from sklearn.ensemble import VotingClassifier
        ensemble = VotingClassifier(
            estimators=[('rf', rf), ('gb', gb), ('lr', lr)],
            voting='soft',
            weights=[0.4, 0.4, 0.2]  # Give more weight to tree-based models
        )

        return ensemble

    def predict(self, emails_or_domains):
        """Make predictions with  confidence scores."""
        if isinstance(emails_or_domains, str):
            emails_or_domains = [emails_or_domains]

        # Check if model is loaded
        if self.calibrated_model is None:
            if not self.load_model():
                print("No trained model found. Please train first.")
                return []

        results = []

        for email_or_domain in tqdm(emails_or_domains, desc="Processing emails"):
            domain = self.extract_domain(email_or_domain)

            # Extract features
            features = self.extract_features(email_or_domain)
            features_df = pd.DataFrame([features])

            # Apply same preprocessing as training
            features_scaled = self.feature_scaler.transform(features_df)
            features_selected = self.feature_selector.transform(features_scaled)

            # Make prediction
            prediction = self.calibrated_model.predict(features_selected)[0]
            probabilities = self.calibrated_model.predict_proba(features_selected)[0]

            # Get confidence (calibrated probability)
            confidence = probabilities[prediction]

            # Get feature contributions
            contributions = self._get_feature_contributions(features, features_df)
            
            # Store for potential use in suspected domain saving
            self.last_top_features = contributions[:5]

            result = {
                'input': email_or_domain,
                'domain': domain,
                'is_disposable': bool(prediction),
                'confidence': float(confidence),
                'probability_legitimate': float(probabilities[0]),
                'probability_disposable': float(probabilities[1]),
                'top_features': contributions[:5],
                'in_training_legitimate': domain in self.legitimate_domains,
                'in_training_disposable': domain in self.disposable_domains,
                'in_suspected_disposable': domain in self.suspected_disposable_domains
            }

            results.append(result)
            
            # NEW: Check if we should save this as a suspected disposable domain
            self._check_and_save_suspected_domain(result)

        return results

    def _check_and_save_suspected_domain(self, result):
        """Check if a domain should be saved as a suspected disposable domain."""
        domain = result['domain']
        
        # Skip if already in training data or suspected list
        if (result['in_training_legitimate'] or 
            result['in_training_disposable'] or 
            result['in_suspected_disposable']):
            return
        
        # Check if it's disposable with high confidence
        if (result['is_disposable'] and 
            result['confidence'] >= self.suspected_domains_threshold):
            
            # Prepare reasons
            reasons = []
            
            # Add confidence level
            reasons.append(f"High confidence ({result['confidence']:.2%})")
            
            # Add top contributing features
            for feature in result['top_features'][:3]:
                if feature['contribution'] > 0.1:  # Only significant contributions
                    reasons.append(f"{feature['feature']}={feature['value']:.3f}")
            
            # Add specific pattern matches if any
            features = self.feature_cache.get(f"features_{domain}", {})
            if features.get('disposable_pattern_score', 0) > 0:
                reasons.append(f"Disposable patterns detected")
            if features.get('domain_entropy', 0) > 3.5:
                reasons.append(f"High entropy ({features['domain_entropy']:.2f})")
            if features.get('digit_ratio', 0) > 0.3:
                reasons.append(f"High digit ratio ({features['digit_ratio']:.2f})")
            
            # Save the suspected domain
            self._save_suspected_domain(domain, result['confidence'], reasons)

    def _get_feature_contributions(self, features, features_df):
        """Get feature contributions using information gain."""
        if not hasattr(self, 'feature_selector'):
            return []

        # Get feature scores from the selector
        feature_scores = self.feature_selector.scores_
        feature_names = features_df.columns

        # Get selected features and their scores
        selected_mask = self.feature_selector.get_support()
        selected_features = []

        for i, (name, selected) in enumerate(zip(feature_names, selected_mask)):
            if selected:
                score = feature_scores[i]
                value = features.get(name, 0)
                selected_features.append({
                    'feature': name,
                    'value': value,
                    'importance': score,
                    'contribution': score * abs(value)
                })

        # Sort by contribution
        selected_features.sort(key=lambda x: x['contribution'], reverse=True)

        return selected_features

    def save_model(self):
        """Save the trained model and configuration."""
        model_data = {
            'calibrated_model': self.calibrated_model,
            'feature_scaler': self.feature_scaler,
            'feature_selector': self.feature_selector,
            'model_config': self.model_config,
            'version': '4.2' 
        }

        with open(self.model_path, 'wb') as f:
            pickle.dump(model_data, f)

    def load_model(self):
        """Load the trained model and configuration."""
        if not os.path.exists(self.model_path):
            self.logger.warning("No saved model found.")
            return False

        try:
            with open(self.model_path, 'rb') as f:
                model_data = pickle.load(f)

            self.calibrated_model = model_data['calibrated_model']
            self.feature_scaler = model_data['feature_scaler']
            self.feature_selector = model_data['feature_selector']
            self.model_config = model_data['model_config']

            self.logger.info("Model loaded successfully.")
            return True
        except Exception as e:
            self.logger.error(f"Error loading model: {str(e)}")
            return False

    def explain_prediction(self, email_or_domain):
        """Provide a detailed explanation of the prediction."""
        results = self.predict(email_or_domain)
        if not results:
            return "No prediction available"

        result = results[0]
        domain = result['domain']

        explanation = f"""
Prediction Explanation for: {email_or_domain}
{'='*50}

Domain: {domain}
Prediction: {'DISPOSABLE' if result['is_disposable'] else 'LEGITIMATE'}
Confidence: {result['confidence']:.1%}

Probability Distribution:
- Legitimate: {result['probability_legitimate']:.1%}
- Disposable: {result['probability_disposable']:.1%}

Training Data Status:
- In Legitimate List: {result['in_training_legitimate']}
- In Disposable List: {result['in_training_disposable']}
- In Suspected Disposable List: {result['in_suspected_disposable']}

Top Contributing Features:
"""

        for i, feature in enumerate(result['top_features'], 1):
            explanation += f"\n{i}. {feature['feature']}"
            explanation += f"\n   Value: {feature['value']:.3f}"
            explanation += f"\n   Importance: {feature['importance']:.3f}"
            explanation += f"\n   Contribution: {feature['contribution']:.3f}"

        # Feature analysis
        features = self.extract_features(email_or_domain)

        explanation += f"\n\nFeature Analysis:"
        explanation += f"\n- Domain Entropy: {features.get('domain_entropy', 0):.3f}"
        explanation += f"\n- Character Diversity: {features.get('char_unique_ratio', 0):.3f}"
        explanation += f"\n- Legitimate Similarity: {features.get('avg_legitimate_similarity', 0):.3f}"
        explanation += f"\n- Disposable Similarity: {features.get('avg_disposable_similarity', 0):.3f}"

        return explanation

    def review_suspected_domains(self, output_path=None):
        """Review all suspected disposable domains collected so far."""
        if not os.path.exists(self.suspected_disposable_path):
            print("No suspected domains file found.")
            return
        
        df = pd.read_csv(self.suspected_disposable_path)
        print(f"\nSuspected Disposable Domains Report")
        print("="*50)
        print(f"Total suspected domains: {len(df)}")
        print(f"\nMost recent 10 domains:")
        print("-"*50)
        
        # Sort by timestamp descending
        df['timestamp'] = pd.to_datetime(df['timestamp'])
        df_sorted = df.sort_values('timestamp', ascending=False)
        
        for idx, row in df_sorted.head(10).iterrows():
            print(f"\nDomain: {row['domain']}")
            print(f"Confidence: {row['confidence']:.3f}")
            print(f"Detected: {row['timestamp'].strftime('%Y-%m-%d %H:%M:%S')}")
            print(f"Reasons: {row['reasons']}")
        
        if output_path:
            df_sorted.to_csv(output_path, index=False)
            print(f"\nFull report saved to: {output_path}")
        
        # Summary statistics
        print(f"\nSummary Statistics:")
        print(f"Average confidence: {df['confidence'].mean():.3f}")
        print(f"Min confidence: {df['confidence'].min():.3f}")
        print(f"Max confidence: {df['confidence'].max():.3f}")
        
        # Most common features
        if 'top_features' in df.columns:
            all_features = []
            for features_str in df['top_features']:
                try:
                    features = json.loads(features_str)
                    all_features.extend(features)
                except:
                    pass
            
            if all_features:
                from collections import Counter
                feature_counts = Counter(all_features)
                print(f"\nMost common features in suspected domains:")
                for feature, count in feature_counts.most_common(5):
                    print(f"- {feature}: {count} occurrences")


def main():
    """Demonstration of the  email detector."""
    print("="*70)
    print(" EMAIL DETECTOR WITH FILE INPUT")
    print("="*70)

    # Initialize detector
    detector = EmailDetector()

    # Train model (if needed)
    if not os.path.exists(detector.model_path):
        print("\nTraining new model...")
        detector.train()
    else:
        print("\nLoading existing model...")
        detector.load_model()

    # Example 1: Test with predefined emails
    print("\n" + "="*70)
    print("EXAMPLE 1: INDIVIDUAL EMAIL TESTING")
    print("="*70)
    
    test_emails = [
        'q5qa2s2@mydefipet.live',
        'sicerol897@hazhab.com',
        'pylasato@cyclelove.cc',
        'hey@e.platypusshoes.co.nz',
        'monday.reply@brighttalk.com',
    ]

    results = detector.predict(test_emails)

    for i, result in enumerate(results, 1):
        status = "DISPOSABLE" if result['is_disposable'] else "LEGITIMATE"
        print(f"\n{i}. Email: {result['input']}")
        print(f"   Status: {status}")
        print(f"   Confidence: {result['confidence']:.1%}")

    # Example 2: Test with file input
    print("\n" + "="*70)
    print("EXAMPLE 2: FILE INPUT TESTING")
    print("="*70)
    
    # Create a sample file if it doesn't exist
    sample_file = "input/test_emails.txt"
    if not os.path.exists(sample_file):
        print(f"\nCreating sample file: {sample_file}")
        with open(sample_file, 'w') as f:
            f.write("# Test emails for detection\n")
            f.write("test123@tempmail.com\n")
    
    # Process emails from file
    results = detector.check_emails_from_file(
        sample_file,
        output_csv="/output/email_check_results.csv",
        output_json="/output/email_check_results.json"
    )

    # Example 3: Review suspected domains
    print("\n" + "="*70)
    print("EXAMPLE 3: SUSPECTED DOMAINS REVIEW")
    print("="*70)
    detector.review_suspected_domains()

    # Example 4: Batch processing from large file
    print("\n" + "="*70)
    print("EXAMPLE 4: BATCH PROCESSING")
    print("="*70)
    
    # Create a larger test file
    batch_file = "/input/batch_emails.txt"
    if not os.path.exists(batch_file):
        print(f"\nCreating batch file: {batch_file}")
        with open(batch_file, 'w') as f:
            f.write("# Batch email processing example\n")
            # Add various test emails
            test_domains = [
                "gmail.com", "tempmail.com", "guerrillamail.com", 
                "outlook.com", "mailinator.com", "example.com"
            ]
            for i in range(20):
                domain = test_domains[i % len(test_domains)]
                f.write(f"user{i}@{domain}\n")
    
    # Process batch file
    detector.check_emails_from_file(batch_file)

    # Example 5: Detailed explanation
    print("\n" + "="*70)
    print("EXAMPLE 5: DETAILED EXPLANATION")
    print("="*70)
    
    explanation = detector.explain_prediction('test123@tempmail456.com')
    print(explanation)


if __name__ == "__main__":
    main()

