#!/bin/sh

TEST_FILE=$1
EXPECTED=${TEST_FILE}.lexer.expected

if [ -z "$TEST_FILE" ]; then
    echo "Usage: $0 <test_file>"
    exit 1
fi

if [ ! -f "$TEST_FILE" ]; then
    echo "Error: Test file not found: $TEST_FILE"
    exit 1
fi

if [ ! -f "$EXPECTED" ]; then
    echo "Error: Expected output not found: $EXPECTED"
    exit 1
fi

./bin/famc $TEST_FILE --debug_lexer > actual_output.txt 2>&1

if diff -u actual_output.txt "$EXPECTED" > diff_output.txt 2>&1; then
    rm -f actual_output.txt diff_output.txt
else
    cat diff_output.txt
    exit 1
fi
