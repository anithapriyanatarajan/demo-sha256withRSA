#!/bin/bash

# Compile and run the Cryptography Education App

echo "Compiling CryptoEducationApp..."
javac CryptoEducationApp.java

if [ $? -eq 0 ]; then
    echo "Compilation successful!"
    echo "Starting the application..."
    echo ""
    java CryptoEducationApp
else
    echo "Compilation failed!"
    exit 1
fi
