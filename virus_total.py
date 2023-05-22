import requests
import hashlib
import argparse
import json

API_KEY = 'YOUR_API_KEY'


def write_to_text_file(value):
    try:
        with open("output.txt", 'w') as file:
            file.write(value)
        print("Output has been written to the file: output.txt")
    except IOError:
        print("Error writing to file: output.txt")


def write_to_json_file(data):
    try:
        with open("output.json", 'w') as file:
            json.dump(data, file, indent=4)
        print("Data has been written to the JSON file: output.json")
    except IOError:
        print("Error writing to JSON file: output.json")


def calculate_file_hash(file_path):
    try:
        with open(file_path, 'rb') as file:
            hasher = hashlib.sha256()
            while True:
                data = file.read(65536)
                if not data:
                    break
                hasher.update(data)

        file_hash = hasher.hexdigest()
        return file_hash
    except IOError:
        print(f"Error reading file: {file_path}")
        return None


def highlight_malicious_data(report):
    try:
        data = json.loads(report)
        if 'data' in data:
            attributes = data['data']['attributes']
            if 'last_analysis_stats' in attributes:
                stats = attributes['last_analysis_stats']
                if stats['malicious'] > 0 or stats['suspicious'] > 0:
                    highlighted_report = report.replace('malicious', '\033[91mmalicious\033[0m').replace('suspicious', '\033[91msuspicious\033[0m')
                    return highlighted_report
    except json.JSONDecodeError:
        pass
    return report


def get_report(url, output_format):
    headers = {'x-apikey': API_KEY}
    response = requests.get(url, headers=headers)

    if response.status_code == 200:
        if output_format == "json":
            report = response.json()
            return json.dumps(report, indent=4)
        elif output_format == "text":
            report = response.text
            return highlight_malicious_data(report)
    else:
        print(f"Error: {response.status_code}")
        return None


def main():
    parser = argparse.ArgumentParser(description='Scan files, domains, IPs, or hashes using the VirusTotal API')
    parser.add_argument('-f', dest='file_path', help='File path')
    parser.add_argument('-d', dest='domain', help='Domain name')
    parser.add_argument('-i', dest='ip_address', help='IP address')
    parser.add_argument('--hash', dest='file_hash', help='File hash value')
    parser.add_argument('-j', action='store_true', help='Display output in JSON format')
    parser.add_argument('-t', action='store_true', help='Display output in text format')
    parser.add_argument('-s', action='store_true', help='Save the output to a file')

    args = parser.parse_args()

    output_format = 'text'
    if args.j:
        output_format = 'json'

    save_file = args.s
    report = ""
    if args.file_path:
        file_hash = calculate_file_hash(args.file_path)
        if file_hash:
            url = f'https://www.virustotal.com/api/v3/files/{file_hash}'
            report = get_report(url, output_format)
    elif args.domain:
        encoded_url = requests.utils.quote(args.domain, safe='')
        url = f'https://www.virustotal.com/api/v3/domains/{encoded_url}'
        report = get_report(url, output_format)
    elif args.ip_address:
        url = f'https://www.virustotal.com/api/v3/ip_addresses/{args.ip_address}'
        report = get_report(url, output_format)
    elif args.file_hash:
        url = f'https://www.virustotal.com/api/v3/files/{args.file_hash}'
        report = get_report(url, output_format)
    else:
        parser.print_help()

    print(report)

    if args.s:
        if output_format == "json":
            write_to_json_file(report)
        else:
            write_to_text_file(report)

if __name__ == '__main__':
    main()
