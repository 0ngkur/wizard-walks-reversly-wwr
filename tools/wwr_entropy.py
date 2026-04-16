import math
import sys
import argparse
import os

def calculate_entropy(data):
    if not data:
        return 0
    entropy = 0
    for i in range(256):
        p_i = data.count(i) / len(data)
        if p_i > 0:
            entropy += -p_i * math.log2(p_i)
    return entropy

def analyze_file(file_path, block_size=1024):
    if not os.path.exists(file_path):
        print(f"Error: File {file_path} not found.")
        return

    file_size = os.path.getsize(file_path)
    total_entropy = 0
    
    with open(file_path, 'rb') as f:
        data = f.read()
        total_entropy = calculate_entropy(data)
        
    print(f"File: {os.path.basename(file_path)}")
    print(f"Size: {file_size} bytes")
    print(f"Overall Entropy: {total_entropy:.4f}")
    
    if total_entropy > 7.0:
        print("Status: Highly likely to be packed or encrypted.")
    elif total_entropy > 6.0:
        print("Status: Possibly packed or contains compressed data.")
    else:
        print("Status: Normal/Unpacked.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Calculate binary entropy")
    parser.add_argument("file", help="Path to the binary file")
    args = parser.parse_argument()
    analyze_file(args.file)
