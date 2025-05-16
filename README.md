# IKick Disposable Email API

A machine learning API for detecting disposable and suspicious email domains to help improve email validation and reduce spam registrations.

## 🚀 Overview

The IKick Disposable Email service uses machine learning to determine if an email domain is legitimate or disposable/temporary. With perfect accuracy metrics in testing (1.000 for accuracy, precision, recall, F1 score, and AUC), it helps:

- Prevent fake account registrations
- Reduce spam
- Improve email validation quality
- Identify suspicious domains

## 🔧 Installation

### Prerequisites
- Python 3.8+
- pip or conda

### Option 1: Using pip
```bash
# Clone the repository
git clone https://github.com/sahayagodson/ikick-disposable-email
cd ikick-disposable-email

# Install dependencies
pip install -r requirements.txt
```

### Option 2: Using conda
```bash
# Clone the repository
git clone [your-repo-url]
cd [repository-directory]

# Create and activate conda environment
conda env create -f environment.yml
conda activate ikick_email

# Install additional requirements
pip install -r requirements.txt
```

## 📋 Project Structure

```
ikick-email/
│
├── ikick_email.py         # Main Python implementation
├── ikick_email.ipynb      # Jupyter Notebook implementation
├── ikick_email_config.json # Configuration settings
├── ikick_email_api.py     # FastAPI implementation
│
├── data/                     # Training data directory
│   ├── legitimate_emails.txt # Known legitimate domains
│   └── disposable_emails.txt # Known disposable domains
│
├── models/                   # Trained model storage
│   └── ikick_email.pkl    # Serialized model file
│
├── output/                   # Results and output files
│   ├── suspected_disposable_domains.csv # Newly detected domains
│   ├── email_check_results.csv          # Batch processing results
│   └── email_check_results.json         # JSON format results
│
└── requirements.txt          # Python dependencies
```

## 📋 Model Performance

The model achieves exceptional performance metrics:

```
Test Accuracy:  1.000
Test Precision: 1.000
Test Recall:    1.000
Test F1:        1.000
Test AUC:       1.000
```

Training process:
1. Balanced training data (185 legitimate domains, 4093 disposable domains)
2. Feature scaling
3. Feature selection (30 best features)
4. Ensemble model training
5. Probability calibration
6. Model evaluation

## ⚙️ Configuration

The detector can be configured using the `ikick_email_config.json` file:

```json
{
    "use_dns": true,           // Use DNS lookups for feature extraction
    "use_whois": false,        // Use WHOIS lookups (slower)
    "max_features": 30,        // Maximum features to select
    "cv_folds": 5,             // Cross-validation folds
    "random_state": 42,        // Random state for reproducibility
    "allow_list_path": "data/legitimate_emails.txt",  // Path to legitimate domains
    "deny_list_path": "data/disposable_emails.txt",   // Path to disposable domains
    "model_path": "models/ikick_email.pkl",        // Model storage path
    "suspected_disposable_path": "output/suspected_disposable_domains.csv", // Output path
    "suspected_domains_threshold": 0.85               // Confidence threshold for detection
}
```

## 🧪 Using the Library

### Python Script Usage

```python
from ikick_email import EmailDetector

# Initialize detector
detector = EmailDetector()

# Load or train model
detector.train()  # Will load existing model or train new one

# Check a single email
result = detector.predict("test@example.com")
print(f"Is disposable: {result[0]['is_disposable']}")
print(f"Confidence: {result[0]['confidence']:.1%}")

# Check multiple emails
results = detector.predict(["user@gmail.com", "test@disposable-temp-mail.com"])

# Get detailed explanation
explanation = detector.explain_prediction("suspicious@domain.com")
print(explanation)

# Check emails from file
detector.check_emails_from_file(
    "input/emails.txt", 
    output_csv="output/results.csv",
    output_json="output/results.json"
)

# Review suspected domains
detector.review_suspected_domains(output_path="output/suspected_report.csv")
```

### Jupyter Notebook Implementation

The project also includes a Jupyter Notebook (`ikick_email.ipynb`) for interactive development and exploration. You can run cells step-by-step to understand how the detection system works.

## 🚀 Running the API

```bash
python ikick_email_api.py
```

The API will be available at:
- API: http://localhost:8000
- Documentation: http://localhost:8000/docs or http://localhost:8000/redoc

## 📡 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/health` | GET | Health check |
| `/api/initialize` | POST | Initialize or load the model |
| `/api/train` | POST | Train or retrain the model |
| `/api/predict` | POST | Predict for a single email |
| `/api/predict/batch` | POST | Predict for multiple emails |
| `/api/explain` | POST | Get detailed prediction explanation |
| `/api/suspected-domains` | GET | Get list of suspected domains |

## 📝 API Usage Examples

### Health Check
```bash
curl http://localhost:8000/health
```

Response:
```json
{
  "status": "ok",
  "message": "IKick Disposable Email API is running"
}
```

### Initialize Model
```bash
curl -X POST http://localhost:8000/api/initialize
```

### Train Model
```bash
curl -X POST -H "Content-Type: application/json" -d '{"force_retrain": false}' http://localhost:8000/api/train
```

### Predict Single Email
```bash
curl -X POST -H "Content-Type: application/json" -d '{"email": "test@example.com"}' http://localhost:8000/api/predict
```

Example with a suspicious email:
```bash
curl -X POST -H "Content-Type: application/json" -d '{"email": "timoy19245@bamsrad.com"}' http://localhost:8000/api/predict
```

Response:
```json
{
  "input": "timoy19245@bamsrad.com",
  "domain": "bamsrad.com",
  "is_disposable": true,
  "confidence": 0.6285922220257467,
  "probability_legitimate": 0.37146777797425322,
  "probability_disposable": 0.6285922220257467,
  "top_features": [
    {
      "feature": "mx_count",
      "value": 1,
      "importance": 0.25616987225285315,
      "contribution": 0.25616987225285315
    }
  ]
}
```

### Predict Multiple Emails
```bash
curl -X POST -H "Content-Type: application/json" -d '{"emails": ["test1@example.com", "disposable@mailinator.com"]}' http://localhost:8000/api/predict/batch
```

### Get Explanation
```bash
curl -X POST -H "Content-Type: application/json" -d '{"email": "test@example.com"}' http://localhost:8000/api/explain
```

### Get Suspected Domains
```bash
curl http://localhost:8000/api/suspected-domains
```

## 📊 API Testing Tools

You can interact with the API using various tools:

1. **Postman**: A popular API client for testing HTTP requests
   - Import the provided collection for quick testing
   - Examples for all endpoints included

2. **Curl**: Command-line tool for making API requests (examples shown above)

3. **Swagger UI**: Automatically generated at http://localhost:8000/docs
   - Interactive documentation
   - Try out API endpoints directly in the browser

4. **ReDoc**: Alternative documentation UI at http://localhost:8000/redoc
   - Clean, responsive documentation

## 📈 Understanding API Responses

The prediction API returns detailed information:

- **input**: The original email address analyzed
- **domain**: Extracted domain from the email
- **is_disposable**: Boolean indicating if the domain is likely disposable
- **confidence**: Confidence score (0-1) for the prediction
- **probability_legitimate**: Probability score that the domain is legitimate
- **probability_disposable**: Probability score that the domain is disposable
- **top_features**: List of features that influenced the decision most
  - **feature**: Name of the feature
  - **value**: Value of the feature for this domain
  - **importance**: How important this feature is to the model
  - **contribution**: How much this feature contributed to this specific prediction

## 📁 Output Directory

The system automatically saves various outputs to the `output/` directory:

- **suspected_disposable_domains.csv**: Newly detected disposable domains with high confidence
- **email_check_results.csv/json**: Results from email checking operations
- **test_emails.txt**: Sample email file for testing
- **batch_emails.txt**: Larger batch of test emails
- **suspected_domains_report.csv**: Comprehensive report on suspected domains

## Screenshots

### API Swagger UI

![alt text](</images/Pasted Graphic 3.png>)

### Health Check Endpoint

![alt text](</images/Pasted Graphic 1.png>)

### Training Output

![alt text](</images/Pasted Graphic 2.png>)

## 🌐 Azure Deployment

For production deployment, you can host this API on Azure using Azure App Service:

### Azure App Service Deployment

1. Create an Azure App Service:
```bash
az group create --name IKickEmailResourceGroup --location eastus
az appservice plan create --name IKickEmailPlan --resource-group IKickEmailResourceGroup --sku B1
az webapp create --name IKickEmailAPI --resource-group IKickEmailResourceGroup --plan IKickEmailPlan --runtime "PYTHON|3.8"
```

2. Configure deployment:
```bash
az webapp config set --name IKickEmailAPI --resource-group IKickEmailResourceGroup --startup-file "gunicorn -w 4 -k uvicorn.workers.UvicornWorker ikick_email_api:app"
```

3. Deploy using Azure CLI or GitHub Actions:
```bash
az webapp deployment source config-local-git --name IKickEmailAPI --resource-group IKickEmailResourceGroup
```

### Azure Best Practices

- Use Azure Key Vault for storing sensitive configuration
- Set up Azure Application Insights for monitoring
- Configure auto-scaling rules based on traffic patterns
- Use Azure Front Door for global distribution and SSL termination

## 🔄 Integration Options

- **Web Applications**: Use the API endpoints to validate emails during registration
- **Email Marketing Systems**: Filter out disposable emails to maintain list quality
- **Customer Support Systems**: Flag potentially suspicious accounts
- **Authentication Systems**: Add an extra layer of verification for accounts using suspicious domains

## 📄 License

[Your license information]

## 🤝 Contributing

[Your contribution guidelines]
