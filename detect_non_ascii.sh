#!/bin/bash
# detect_non_ascii.sh

for file in $(find . -name "*.c" -o -name "*.h"); do
    if [ -f "$file" ]; then
        # Verifier si le fichier contient des caracteres non-ASCII
        if LC_ALL=C grep -q '[^[:print:][:space:]]' "$file" 2>/dev/null; then
            echo "=== Non-ASCII characters in: $file ==="
            LC_ALL=C grep -n '[^[:print:][:space:]]' "$file" 2>/dev/null || true
            echo ""
        fi
    fi
done