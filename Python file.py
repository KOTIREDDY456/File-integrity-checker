# File-integrity-checker
import hashlib
import os
import sys

def calculate_hash(file_path):
    """Calculate SHA-256 hash of a file"""
    sha256 = hashlib.sha256()
    
    with open(file_path, "rb") as f:
        for block in iter(lambda: f.read(4096), b""):
            sha256.update(block)
    
    return sha256.hexdigest()


def store_hash(file_path, hash_value):
    """Store hash in a .hash file"""
    with open(file_path + ".hash", "w") as f:
        f.write(hash_value)


def check_integrity(file_path):
    """Check file integrity"""
    if not os.path.exists(file_path + ".hash"):
        print("❌ No hash file found. Run initialization first.")
        return

    original_hash = open(file_path + ".hash").read()
    current_hash = calculate_hash(file_path)

    if original_hash == current_hash:
        print("✅ File integrity intact. No changes detected.")
    else:
        print("⚠️ File has been modified!")
        print("Original Hash:", original_hash)
        print("Current Hash :", current_hash)


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage:")
        print("  python integrity_checker.py init <file>")
        print("  python integrity_checker.py check <file>")
        sys.exit(1)

    action = sys.argv[1]
    file_path = sys.argv[2]

    if not os.path.exists(file_path):
        print("❌ File does not exist.")
        sys.exit(1)

    if action == "init":
        hash_value = calculate_hash(file_path)
        store_hash(file_path, hash_value)
        print("✅ Hash generated and stored successfully.")
        print("Hash:", hash_value)

    elif action == "check":
        check_integrity(file_path)

    else:
        print("❌ Invalid action. Use init or check.")
