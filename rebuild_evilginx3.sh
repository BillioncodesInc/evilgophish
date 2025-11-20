#!/usr/bin/env bash

# Simple script to rebuild evilginx3 binary only
# Usage: ./rebuild_evilginx3.sh

script_name="evilginx3 rebuild"

function print_good () {
    echo -e "[${script_name}] \x1B[01;32m[+]\x1B[0m $1"
}

function print_error () {
    echo -e "[${script_name}] \x1B[01;31m[-]\x1B[0m $1"
}

function print_info () {
    echo -e "[${script_name}] \x1B[01;34m[*]\x1B[0m $1"
}

# Check if evilginx3 directory exists
if [[ ! -d "evilginx3" ]]; then
    print_error "evilginx3 directory not found!"
    print_error "Make sure you're running this script from the evilgophish root directory"
    exit 1
fi

print_info "Rebuilding evilginx3 binary..."

# Navigate to evilginx3 directory and build
cd evilginx3 || exit 1

# Build the binary
if go build -o evilginx3; then
    print_good "Successfully rebuilt evilginx3 binary!"
    print_info "Binary location: $(pwd)/evilginx3"
    
    # Check if binary is executable
    if [[ -x "evilginx3" ]]; then
        print_good "Binary is executable and ready to use"
    else
        print_info "Making binary executable..."
        chmod +x evilginx3
        print_good "Binary is now executable"
    fi
else
    print_error "Failed to build evilginx3!"
    print_error "Check the error messages above for details"
    exit 1
fi

cd ..

print_good "Rebuild complete!"
print_info "You can now run: cd evilginx3 && ./evilginx3 -feed -g /path/to/gophish.db"
