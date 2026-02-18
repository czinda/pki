#!/bin/bash
# Simple markdown to HTML converter using built-in tools

for file in WEBHOOK-IMPLEMENTATION.md DASHBOARD-IMPLEMENTATION.md; do
    if [ -f "$file" ]; then
        html_file="${file%.md}.html"
        echo "Converting $file to $html_file..."
        
        cat > "$html_file" << 'HEADER'
<!DOCTYPE html>
<html>
<head>
<meta charset="UTF-8">
<style>
body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; max-width: 900px; margin: 40px auto; padding: 20px; line-height: 1.6; }
h1 { border-bottom: 2px solid #0066cc; padding-bottom: 10px; }
h2 { border-bottom: 1px solid #ddd; padding-bottom: 5px; margin-top: 30px; }
h3 { margin-top: 25px; }
code { background: #f4f4f4; padding: 2px 6px; border-radius: 3px; font-family: 'SF Mono', Consolas, monospace; }
pre { background: #f4f4f4; padding: 15px; border-radius: 5px; overflow-x: auto; }
pre code { background: none; padding: 0; }
table { border-collapse: collapse; width: 100%; margin: 15px 0; }
th, td { border: 1px solid #ddd; padding: 10px; text-align: left; }
th { background: #f8f8f8; }
blockquote { border-left: 4px solid #0066cc; margin: 0; padding-left: 20px; color: #666; }
a { color: #0066cc; }
</style>
</head>
<body>
HEADER
        
        # Basic markdown to HTML conversion
        sed -e 's/^# \(.*\)/<h1>\1<\/h1>/' \
            -e 's/^## \(.*\)/<h2>\1<\/h2>/' \
            -e 's/^### \(.*\)/<h3>\1<\/h3>/' \
            -e 's/^#### \(.*\)/<h4>\1<\/h4>/' \
            -e 's/\*\*\([^*]*\)\*\*/<strong>\1<\/strong>/g' \
            -e 's/`\([^`]*\)`/<code>\1<\/code>/g' \
            -e 's/^- \(.*\)/<li>\1<\/li>/' \
            -e 's/^---$/<hr>/' \
            -e 's/^$/\n<p>\n/' \
            "$file" >> "$html_file"
        
        echo "</body></html>" >> "$html_file"
        echo "Created: $html_file"
    fi
done
