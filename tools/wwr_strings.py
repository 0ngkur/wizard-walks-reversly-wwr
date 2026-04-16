import re
import sys
import argparse
import os

# Regex patterns for interesting strings
PATTERNS = {
    "IPv4": r'\b(?:\d{1,3}\.){3}\d{1,3}\b',
    "URL": r'https?://(?:[-\w.]|(?:%[\da-fA-F]{2}))+',
    "Email": r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
    "File Path": r'[a-zA-Z]:\\[\w\\\-\s.]+\.\w{2,4}|\/[\w\-\/.]+\.\w{2,4}',
    "Registry": r'HKEY_(?:LOCAL_MACHINE|CURRENT_USER|USERS|CLASSES_ROOT|CURRENT_CONFIG)[\w\\]+',
    "Variable/Flag": r'[a-zA-Z_][a-zA-Z0-9_]{5,}'
}

def extract_strings(file_path, min_len=4):
    if not os.path.exists(file_path):
        return []

    with open(file_path, 'rb') as f:
        content = f.read()
        
    # Extract ASCII strings
    ascii_strings = re.findall(rb'[ -~]{' + str(min_len).encode() + rb',}', content)
    # Extract Unicode strings (wide character)
    unicode_strings = re.findall(rb'(?:[ -~]\x00){' + str(min_len).encode() + rb',}', content)
    
    all_strings = []
    for s in ascii_strings:
        try:
            all_strings.append(s.decode('ascii'))
        except:
            pass
    for s in unicode_strings:
        try:
            all_strings.append(s.decode('utf-16le'))
        except:
            pass
            
    return list(set(all_strings))

def find_interesting(strings):
    found = {k: [] for k in PATTERNS}
    for s in strings:
        for name, pattern in PATTERNS.items():
            if re.search(pattern, s):
                found[name].append(s)
    
    # Filter and sort
    for k in found:
        found[k] = sorted(list(set(found[k])))
    return found

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Advanced string extractor for binary analysis")
    parser.add_argument("file", help="Path to the binary file")
    parser.add_argument("--min", type=int, default=5, help="Minimum string length")
    args = parser.parse_args()
    
    all_strs = extract_strings(args.file, args.min)
    interesting = find_interesting(all_strs)
    
    print(f"--- Analysis for {os.path.basename(args.file)} ---")
    print(f"Total strings found: {len(all_strs)}")
    print("\n--- Interesting Patterns ---")
    for category, items in interesting.items():
        if items:
            print(f"\n[{category}]")
            for item in items[:20]: # Show top 20
                print(f"  {item}")
            if len(items) > 20:
                print(f"  ... and {len(items)-20} more")
