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