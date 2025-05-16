#!/bin/bash
set -e

# Colors for output
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

echo -e "${GREEN}=========================================${NC}"
echo -e "${GREEN}    IKick Disposable Email Setup         ${NC}"
echo -e "${GREEN}=========================================${NC}"

# Create necessary directories
echo -e "\n${YELLOW}Creating project directories...${NC}"
mkdir -p input models output data

# Check if conda is available
USE_CONDA=false
if command -v conda &> /dev/null; then
    echo -e "\n${YELLOW}Conda detected. Would you like to use conda for environment setup? (y/n)${NC}"
    read -r use_conda_response
    if [[ "$use_conda_response" =~ ^[Yy]$ ]]; then
        USE_CONDA=true
    fi
fi

if [ "$USE_CONDA" = true ]; then
    echo -e "\n${YELLOW}Setting up conda environment...${NC}"
    
    # Check if environment exists
    if conda info --envs | grep -q "ikick_email"; then
        echo -e "${YELLOW}IKick Disposable Email environment already exists. Updating...${NC}"
        conda env update -f environment.yml
    else
        echo -e "${YELLOW}Creating new conda environment...${NC}"
        conda env create -f environment.yml
    fi
    
    echo -e "\n${YELLOW}Activating conda environment...${NC}"
    # shellcheck disable=SC1091
    source "$(conda info --base)/etc/profile.d/conda.sh"
    conda activate ikick_email
    
    echo -e "\n${YELLOW}Installing additional pip requirements...${NC}"
    pip install -r requirements.txt
else
    echo -e "\n${YELLOW}Setting up using pip...${NC}"
    
    # Check if virtualenv is installed, install if not
    if ! command -v virtualenv &> /dev/null; then
        echo -e "${YELLOW}Installing virtualenv...${NC}"
        pip install virtualenv
    fi
    
    # Create and activate virtual environment
    echo -e "${YELLOW}Creating virtual environment...${NC}"
    virtualenv venv
    
    # Activate virtual environment based on OS
    if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo -e "${YELLOW}Activating virtual environment (Unix/Mac)...${NC}"
        source venv/bin/activate
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo -e "${YELLOW}Activating virtual environment (Windows)...${NC}"
        source venv/Scripts/activate
    else
        echo -e "${RED}Unknown OS. Please activate the virtual environment manually.${NC}"
        exit 1
    fi
    
    echo -e "\n${YELLOW}Installing requirements...${NC}"
    pip install -r requirements.txt
fi

echo -e "\n${GREEN}Setting up sample data files...${NC}"
# Only create if they don't exist
if [ ! -f "data/legitimate_emails.txt" ]; then
    echo -e "${YELLOW}Creating sample legitimate email domains list...${NC}"
    echo "gmail.com
outlook.com
yahoo.com
hotmail.com
aol.com
protonmail.com
icloud.com" > data/legitimate_emails.txt
fi

if [ ! -f "data/disposable_emails.txt" ]; then
    echo -e "${YELLOW}Creating sample disposable email domains list...${NC}"
    echo "tempmail.com
guerrillamail.com
mailinator.com
10minutemail.com
throwawaymail.com
temp-mail.org
fakeinbox.com" > data/disposable_emails.txt
fi

echo -e "\n${GREEN}=========================================${NC}"
echo -e "${GREEN}    Setup Complete!                      ${NC}"
echo -e "${GREEN}=========================================${NC}"

if [ "$USE_CONDA" = true ]; then
    echo -e "${YELLOW}To activate the environment later, run:${NC}"
    echo -e "    conda activate ikick_email"
else
    echo -e "${YELLOW}To activate the environment later, run:${NC}"
    if [[ "$OSTYPE" == "darwin"* ]] || [[ "$OSTYPE" == "linux-gnu"* ]]; then
        echo -e "    source venv/bin/activate"
    elif [[ "$OSTYPE" == "msys" ]] || [[ "$OSTYPE" == "win32" ]]; then
        echo -e "    source venv/Scripts/activate"
    fi
fi

echo -e "\n${YELLOW}To use IKick Disposable Email:${NC}"
echo -e "    python ikick_email.py    # For CLI interface"
echo -e "    python ikick_email_api.py # For API interface"
echo -e "    jupyter notebook ikick_email.ipynb # For interactive notebook"
