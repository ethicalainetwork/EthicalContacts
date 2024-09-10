## Secure Telegram Contacts Viewer

<img width="1171" alt="Screenshot 2024-09-10 at 11 51 46 PM" src="https://github.com/user-attachments/assets/b00b17e6-3e6e-420e-b60a-b7f5a9bfa03d">
<img width="724" alt="Screenshot 2024-09-11 at 12 21 25 AM" src="https://github.com/user-attachments/assets/b955a188-efc2-420a-9762-a86d5397ee4e">


You can export your Telegram contacts via Telegram desktop app (Settings -> Advanced -> Export Telegram data).



Open terminal and paste and press enter:
```
bash run.sh
```

Open browser and go to: http://localhost:5000/






To convert the exported contacts (JSON file) to a VCF file and import it by your phone, use this script.

Usage
python3 telegram_json_to_vcf.py [--add-all] json_file vcf_file
Arguments:
--add-all: Whether to add all of the contacts or add them one by one
json_file: Path to JSON file
vcf_file: Path to VCF file

Examples:
python3 telegram_json_to_vcf.py --add-all ./contacts.json ./contacts.vcf
python3 telegram_json_to_vcf.py ./contacts.json .

Notes
JSON file must have UTF-8 encoding.
You can specify the VCF file name (see the examples).
In case another file exists with the same name, then the VCF file is renamed.
