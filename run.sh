#!/bin/bash

# Check operating system
if [[ $(uname -s) == 'Darwin' ]]; then
    # macOS
    OS='macOS'
    PYTHON_CMD='python3'
    PIP_CMD='pip3'
elif [[ $(uname -s) == 'Linux' && -e /mnt/c ]]; then
    # WSL (Windows Subsystem for Linux)
    OS='WSL'
    PYTHON_CMD='python3'
    PIP_CMD='pip3'
elif [[ $(uname -s) == 'Linux' ]]; then
    # Generic Linux
    OS='Linux'
    PYTHON_CMD='python3'
    PIP_CMD='pip3'
else
    echo "Unsupported operating system."
    exit 1
fi

# Check if Python is installed
if ! command -v $PYTHON_CMD &> /dev/null; then
    echo "Python is not installed. Installing..."
    if [[ $OS == 'macOS' ]]; then
        # Install Python on macOS (using Homebrew, assumed to be installed)
        brew install python3
    elif [[ $OS == 'Linux' || $OS == 'WSL' ]]; then
        # Install Python on Linux (using package manager, adjust as needed)
        sudo apt-get update  # Update package lists
        sudo apt-get install -y python3 python3-pip  # Install Python and pip
    fi
fi

# Install Flask app dependencies
$PIP_CMD install -r r.t

# Start Flask app
$PYTHON_CMD app.py --port 5055