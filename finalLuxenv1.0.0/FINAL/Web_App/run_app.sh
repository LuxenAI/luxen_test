#!/bin/bash

# Set environment variables
export AWS_ACCESS_KEY_ID=AKIAUMHDSKJ2ZE3IPDNA
export AWS_DEFAULT_REGION=us-east-2
export AWS_SECRET_ACCESS_KEY=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
export GEMINI_API_KEY=AIzaSyDATlzkJ-auty-coYJEkcl1PoJFd1Vj13o
export PYTHONUNBUFFERED=1
export S3_BUCKET_NAME=luxen-test-storage-v1
export FLASK_APP=app.py
export FLASK_ENV=development

# Debug: Print environment variables (first few characters only)
echo "Environment variables set:"
echo "GEMINI_API_KEY: ${GEMINI_API_KEY:0:5}..."
echo "AWS_ACCESS_KEY_ID: ${AWS_ACCESS_KEY_ID:0:5}..."
echo "S3_BUCKET_NAME: $S3_BUCKET_NAME"

# Run the application using flask on port 5001
flask run --port=5001 