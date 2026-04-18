#!/bin/bash

# Update sed command for compatibility with Debian (GNU sed)

# Example sed commands that were using BSD-style syntax:
# sed -i '' 's/foo/bar/g' file.txt

# Changed to:
sed -i 's/foo/bar/g' file.txt

# Include your remaining sed commands as needed
