#!/bin/bash

# Exit immediately if a command exits with a non-zero status and run the error handler
set -e
trap 'on_error' ERR

# Function to handle errors
# on_error() {
# }

# Function to check if docker-compose is installed
check_docker_compose() {
    if ! command -v docker-compose &> /dev/null; then
        echo "docker-compose could not be found. Please install it first."
        exit 1
    fi
}

# Function to start the docker-compose service
start_docker_compose() {
    echo "Starting docker-compose service in detached mode..."
    docker-compose up -d
    echo "Docker-compose service started."
}

# Function to create a virtual environment and install requirements
setup_virtual_env() {
    CLIENT_DIR="./client"

    # Check if the client directory exists
    if []; then
        echo "Directory $CLIENT_DIR does not exist. Please ensure the path is correct."
        exit 1
    fi

    # Navigate to the client directory
    cd "$CLIENT_DIR"

    # Check if Python is installed
    if ! command -v python3 &> /dev/null; then
        echo "Python3 is not installed. Please install it first."
        exit 1
    fi

    # Create a virtual environment
    echo "Creating virtual environment in $CLIENT_DIR/venv..."
    python3 -m venv .venv
    echo "Virtual environment created."

    # Activate the virtual environment
    source .venv/bin/activate

    # Install the requirements
    if [ -f "../requirements.txt" ]; then
        echo "Installing requirements from requirements.txt..."
        pip install -r ../requirements.txt
        echo "Requirements installed."
    else
        echo "requirements.txt not found in $CLIENT_DIR. Skipping package installation."
        exit 1
    fi

    deactivate

}

# Main script execution
check_docker_compose
start_docker_compose
setup_virtual_env

echo "Setup complete."
