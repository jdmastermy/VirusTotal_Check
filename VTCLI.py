import argparse
from vt_utils import check_ip_reputation, check_url_reputation, check_hash_reputation
from app_utils import save_data, headers_map, log_event

def main(args):
    data_type = args.type
    output_format = args.format
    results = []

    if args.data:
        input_data = args.data.split(',')
    else:
        with open(args.file, 'r') as f:
            input_data = f.readlines()

    for data in input_data:
        data = data.strip()
        if data:
            result = check_data(data, data_type)
            results.append(result)
            log_event(f"Processed {data_type} - {data}")

    headers = headers_map[data_type]
    save_data(args.output, results, output_format, headers)
    print("\nData saved successfully!")

def check_data(data, data_type):
    if data_type == "IP":
        return check_ip_reputation(data)
    elif data_type == "URL":
        return check_url_reputation(data)
    elif data_type in ["MD5 Hash", "SHA1 Hash", "SHA256 Hash"]:
        return check_hash_reputation(data)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="VTChecker CLI by JediMaster.")

    parser.add_argument('-t', '--type', required=True, 
                        choices=["IP", "URL", "MD5 Hash", "SHA1 Hash", "SHA256 Hash"], 
                        help="Specify the type of data you want to check. It can be an IP address, URL, or a hash.")
    parser.add_argument('-d', '--data', 
                        help="Provide the data directly as a comma-separated list. For example, '8.8.8.8,8.8.4.4'. Either this or --file must be provided.")
    parser.add_argument('-f', '--file', 
                        help="Path to an input file containing the data to be checked. Data should be listed line by line. Either this or --data must be provided.")
    parser.add_argument('-o', '--output', required=True, 
                        help="Specify the path where you'd like the output file to be saved. For example, 'output.csv'.")
    parser.add_argument('-fmt', '--format', choices=["CSV", "JSON", "TXT"], default="CSV", 
                        help="Specify the format for the output file. The default is CSV, but JSON and TXT are also available.")

    args = parser.parse_args()
    
 
    if not (args.data or args.file):
        parser.error("Either --data or --file must be provided.")
    
    main(args)
