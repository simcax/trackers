#!/bin/bash

# Build script for Clever Cloud deployment
# This script builds the CSS assets needed for the application

echo "Starting build process..."

# Check if npm is available
if command -v npm &> /dev/null; then
    echo "npm found, installing dependencies..."
    npm install
    
    echo "Building CSS assets..."
    npm run build-css-prod
    
    echo "Build completed successfully!"
else
    echo "npm not found, skipping CSS build"
    echo "Using pre-built CSS from repository"
fi

echo "Build process finished."