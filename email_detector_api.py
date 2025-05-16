#!/usr/bin/env python
import sys
import os

# --- MODIFIED PACKAGE CHECK ---
def check_and_import_packages():
    required_packages_map = {
        "uvicorn": "uvicorn",
        "fastapi": "fastapi",
        "pandas": "pandas",
        "sklearn": "scikit-learn"  # sklearn is the import name for scikit-learn
    }
    
    actually_missing_for_import = []
    pip_names_for_missing = []

    for import_name, pip_name in required_packages_map.items():
        try:
            print(f"DEBUG: Attempting to import '{import_name}'")
            __import__(import_name)
            print(f"DEBUG: Successfully imported '{import_name}'")
        except ImportError as e:
            print(f"DEBUG: Failed to import '{import_name}': {e}")
            actually_missing_for_import.append(import_name)
            pip_names_for_missing.append(pip_name)

    if actually_missing_for_import:
        error_message_pkgs_list = actually_missing_for_import
        pip_install_suggestion_list = list(set(pip_names_for_missing + ["numpy"]))

        print(f"\nError: Missing required packages: {', '.join(error_message_pkgs_list)}\n")
        print(f"Please install them using: pip install {' '.join(pip_install_suggestion_list)}\n")
        print("Alternatively, use the provided setup script:")
        print("   bash setup_env.sh\n")
        print("Or if using conda, make sure to activate your environment and install all dependencies:")
        print("   conda env update -f environment.yml")
        print("   conda activate email_detector")
        print("   pip install -r requirements.txt")
        sys.exit(1)
    
    print("DEBUG: All required packages successfully imported and available for use.")
    global uvicorn, fastapi, pd, sklearn
    import uvicorn
    import fastapi
    import pandas as pd
    import sklearn

check_and_import_packages()

# Now that we've checked dependencies, import the required packages
from fastapi import FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import RedirectResponse
from pydantic import BaseModel
from typing import List, Optional
import json
from pathlib import Path

# Import the EmailDetector class from your notebook
try:
    from email_detector import EmailDetector
except ImportError as e:
    print("Error: Could not import EmailDetector class.")
    print("Make sure email_detector.py is in the same directory.")
    sys.exit(1)

# Create data directories if they don't exist
os.makedirs('input', exist_ok=True)
os.makedirs('models', exist_ok=True)
os.makedirs('output', exist_ok=True)

# Initialize the detector
detector = EmailDetector()

# Create the FastAPI app
app = FastAPI(
    title="Email Detector API",
    description="API for detecting disposable and suspicious email domains",
    version="1.0.0"
)

# Add CORS middleware to allow cross-origin requests
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Define request and response models
class EmailRequest(BaseModel):
    email: str

class EmailBatchRequest(BaseModel):
    emails: List[str]

class TrainRequest(BaseModel):
    force_retrain: bool = False

# Health check endpoint
@app.get("/health")
async def health_check():
    return {"status": "ok", "message": "Email Detector API is running"}

# Root endpoint to redirect to /docs
@app.get("/")
async def root_redirect_to_docs():
    return RedirectResponse(url="/docs")

# Initialize model endpoint
@app.post("/api/initialize")
async def initialize_model():
    """Initialize or load the model"""
    success = detector.load_model()
    
    if not success:
        print("No model found, training new model...")
        detector.train()
        return {"status": "success", "message": "Model trained successfully"}
    
    return {"status": "success", "message": "Model loaded successfully"}

# Train model endpoint
@app.post("/api/train")
async def train_model(request: TrainRequest):
    """Train or retrain the model"""
    success = detector.train(force_retrain=request.force_retrain)
    return {"status": "success", "message": "Model training completed"}

# Predict single email endpoint
@app.post("/api/predict")
async def predict_email(request: EmailRequest):
    """Predict whether a single email is disposable or legitimate"""
    if not request.email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    results = detector.predict(request.email)
    
    if not results:
        raise HTTPException(status_code=500, detail="Prediction failed")
    
    return results[0]

# Batch predict emails endpoint
@app.post("/api/predict/batch")
async def predict_batch(request: EmailBatchRequest):
    """Predict whether multiple emails are disposable or legitimate"""
    if not request.emails:
        raise HTTPException(status_code=400, detail="Email list is empty")
    
    results = detector.predict(request.emails)
    
    if not results:
        raise HTTPException(status_code=500, detail="Prediction failed")
    
    return {"results": results}

# Explain prediction endpoint
@app.post("/api/explain")
async def explain_prediction(request: EmailRequest):
    """Get a detailed explanation of the prediction for an email"""
    if not request.email:
        raise HTTPException(status_code=400, detail="Email is required")
    
    explanation = detector.explain_prediction(request.email)
    
    if not explanation:
        raise HTTPException(status_code=500, detail="Explanation failed")
    
    return {"email": request.email, "explanation": explanation}

# Get suspected domains endpoint
@app.get("/api/suspected-domains")
async def get_suspected_domains():
    """Get a list of suspected disposable domains"""
    if not os.path.exists(detector.suspected_disposable_path):
        return {"domains": [], "message": "No suspected domains found"}
    
    try:
        import pandas as pd
        df = pd.read_csv(detector.suspected_disposable_path)
        domains = df.to_dict(orient="records")
        return {"domains": domains, "count": len(domains)}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Error loading suspected domains: {str(e)}")

# Main entry point to run the API directly
if __name__ == "__main__":
    # --- MOVED DEBUG BLOCK HERE ---
    print(f"DEBUG: Running with Python executable: {sys.executable}")
    print(f"DEBUG: sys.path: {sys.path}")
    print(f"DEBUG: Current working directory: {os.getcwd()}")
    # Check if VIRTUAL_ENV is set, which indicates a venv is active
    print(f"DEBUG: VIRTUAL_ENV environment variable: {os.environ.get('VIRTUAL_ENV')}")
    # --- END MOVED DEBUG BLOCK ---

    print(f"\nStarting Email Detector API using Python from: {sys.executable}")
    print("Uvicorn will be running on http://localhost:8000 (or http://127.0.0.1:8000)")
    print("API documentation available at http://localhost:8000/docs and http://localhost:8000/redoc")
    print("\n--- API Usage Examples (run these in a new terminal) ---")
    print("Health Check (GET):")
    print("  curl http://localhost:8000/health")
    print("\nInitialize Model (POST):")
    print("  curl -X POST http://localhost:8000/api/initialize")
    print("\nTrain Model (POST, optional: force retrain):")
    print("  curl -X POST -H \"Content-Type: application/json\" -d '{\"force_retrain\": false}' http://localhost:8000/api/train")
    print("  (To force retrain: curl -X POST -H \"Content-Type: application/json\" -d '{\"force_retrain\": true}' http://localhost:8000/api/train)")
    print("\nPredict Single Email (POST):")
    print("  curl -X POST -H \"Content-Type: application/json\" -d '{\"email\": \"test@example.com\"}' http://localhost:8000/api/predict")
    print("\nPredict Batch Emails (POST):")
    print("  curl -X POST -H \"Content-Type: application/json\" -d '{\"emails\": [\"test1@example.com\", \"disposable@mailinator.com\"]}' http://localhost:8000/api/predict/batch")
    print("\nExplain Prediction (POST):")
    print("  curl -X POST -H \"Content-Type: application/json\" -d '{\"email\": \"test@example.com\"}' http://localhost:8000/api/explain")
    print("\nGet Suspected Domains (GET):")
    print("  curl http://localhost:8000/api/suspected-domains")
    print("\n---------------------------------------------------------\n")
    
    uvicorn.run("email_detector_api:app", host="127.0.0.1", port=8000, reload=True)