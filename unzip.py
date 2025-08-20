import os
import zipfile
import re

# 🔧 Set paths
ZIP_FILE = r"path"
OUTPUT_FOLDER = r"path"

def sanitize_path(path):
    """
    Sanitize each folder/file name separately
    to preserve folder structure but replace invalid characters.
    """
    safe_parts = []
    for part in path.split("/"):  # ZIP always uses "/" internally
        safe_parts.append(re.sub(r'[<>:"/\\|?*]', "_", part))
    return os.path.join(*safe_parts)

def safe_extract(zip_path, extract_to):
    os.makedirs(extract_to, exist_ok=True)

    with zipfile.ZipFile(zip_path, 'r') as zf:
        for member in zf.infolist():
            safe_name = sanitize_path(member.filename)
            dest_path = os.path.join(extract_to, safe_name)

            if member.is_dir():
                # ✅ Create folder safely
                os.makedirs(dest_path, exist_ok=True)
            else:
                # ✅ Ensure parent folder exists
                os.makedirs(os.path.dirname(dest_path), exist_ok=True)
                try:
                    with zf.open(member) as source, open(dest_path, "wb") as target:
                        target.write(source.read())
                except Exception as e:
                    print(f"⚠️ Skipped: {member.filename} -> {e}")

    print(f"✅ Extraction completed to {extract_to}")

if __name__ == "__main__":
    if not os.path.exists(ZIP_FILE):
        print("❌ ZIP file not found!")
    else:
        safe_extract(ZIP_FILE, OUTPUT_FOLDER)