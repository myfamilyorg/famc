#!/bin/sh

if [ $# -ne 1 ]; then
    echo "Usage: $0 <directory_or_file>"
    echo "  Scans all *.fam files in the directory (non-recursive)"
    echo "  or runs on a single file if a file is given"
    exit 1
fi

echo "Running lexer tests on $1...";
INPUT="$1"

for file in "$INPUT"/*.fam; do
    if [ -f "$file" ]; then
        echo "Testing $file..."
        ./scripts/test_lexer.sh $file
        RES=$?;
        if [ "$RES" != "0" ]; then
            echo "TEST FAILED: $file (non-zero exit code)"
            exit 1
        fi
    fi
done
echo "All tests passed!";
