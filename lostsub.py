import os
import argparse
import time
import subprocess
import sys
import re

def print_banner():
    banner = r"""
		.__                  __              ___.    
		|  |   ____  _______/  |_  ________ _\_ |__  
		|  |  /  _ \/  ___/\   __\/  ___/  |  \ __ \ 
		|  |_(  <_> )___ \  |  |  \___ \|  |  / \_\ \
		|____/\____/____  > |__| /____  >____/|___  /
                \/            \/          \/ 
            
            			by @0xlipon with ❤

	My Github Profile: 		https://github.com/0xlipon
	
    """
    print(banner)

def run_command(command, description, retries=3, delay=5):
    """Run the command and if you encounter an error, try again"""
    attempt = 0
    print(f"\033[34mINFO:\033[0m \033[31m {description}\033[0m")
    while attempt < retries:
        result = os.system(command)
        if result == 0:
            print(f"\033[34mINFO:\033[0m \033[32m The command completed successfully.\033[0m")
            return
        attempt += 1
        print(f"\033[34mERROR:\033[0m \033[31m The command failed, waiting for {delay} seconds and retrying... ({attempt}/{retries})\033[0m")
        time.sleep(delay)
    print(f"\033[34mERROR:\033[0m \033[31m The command failed after {retries} attempts.\033[0m")

def gather_subdomains(domain):
    """Collecting subdomains with various tools"""
    
    VT_API_KEY = '0cdaaea08e6982bd2149b417c570c692201347e22fae07d0e90e66cf849941f3'

    # Check if the API key is missing
    if VT_API_KEY == 'your_virustotal_api_key_here' or not VT_API_KEY.strip():
        print("\033[34mERROR:\033[0m \033[31m Your VirusTotal API key is missing. Please replace 'your_virustotal_api_key_here' with your actual API key in the script.\033[0m")
        sys.exit(1)  # Exit the program
        
    commands = [
	(f'subdominator -d {domain} -o subdominator', "Collecting subdomains with Subdominator"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://crt.sh/?q=%25.{domain}&output=json" | jq -r 'if type=="array" then . else empty end' | jq -r '.[].name_value' | sed 's/\\*\\.//g' | sort -u | anew crt''', "Collecting subdomains from crt.sh"),
        (f'''curl --socks5 127.0.0.1:9050 -s --request GET --url 'https://api.securitytrails.com/v1/domain/{domain}/subdomains?children_only=true&include_inactive=false' --header 'APIKEY: WGPKBLH-RODuVKrhDQ8WPb2HSgrKfaa8' --header 'accept: application/json' | jq -r '.subdomains[] | . + ".{domain}"' | anew securitytrails''', "Collecting subdomains from SecurityTrails"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://www.virustotal.com/api/v3/domains/{domain}/subdomains" -H "x-apikey: {VT_API_KEY}" | jq -r '.data[]?.attributes?.last_https_certificate?.extensions?.subject_alternative_name[]? // empty' | sort -u | anew virustotal''', "Collecting subdomains from VirusTotal"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names" | jq -r '.[].dns_names[]' | sort -u | anew certspotter''', "Collecting subdomains from CertSpotter API"),
        (f'''curl --socks5 127.0.0.1:9050 -s "http://web.archive.org/cdx/search/cdx?url=*.{domain}/*&output=text&fl=original&collapse=urlkey" | sed -e 's_https*://__' -e 's/\\/.*//' | sort -u | anew webarchive''', "Collecting subdomains from Web Archive"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://jldc.me/anubis/subdomains/{domain}" | grep -Po '((http|https):\\/\\/)?([\\w.-]+\\.[\\w]+\\.[A-z]+)' | sort -u | anew jldc''', "Collecting subdomains from JLDC API"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://api.hackertarget.com/hostsearch/?q={domain}" | awk -F',' '{{print $1}}' | anew hackertarget''', "Collecting subdomains from HackerTarget API"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://otx.alienvault.com/api/v1/indicators/domain/tesla.com/url_list?limit=10000000000000000000000000000000000000000000000000000000000000000&page=1" | grep -o '"hostname": *"[^"]*' | sed 's/"hostname": "//' | sort -u | anew alienvault''', "Collecting subdomains from AlienVault API"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://api.subdomain.center/?domain={domain}" | jq -r '.[]' | sort -u | anew subdomaincenter''', "Collecting subdomains from Subdomain Center API"),
        (f'''curl --socks5 127.0.0.1:9050 -s "https://rapiddns.io/subdomain/{domain}?full=1" | grep -oE "[a-zA=Z0-9.-]+\\.{domain}" | sort -u | anew rapiddns''', "Collecting subdomains from RapidDNS API"),
        (f'subfinder -d {domain} -all -recursive | anew subfinder', "Collecting subdomains from Subfinder"),
        (f'assetfinder -subs-only {domain} | tee assetfinder', "Collecting subdomains from Assetfinder"),
	(f'traceninja -d {domain} -o traceninja', "Collecting subdomains from TraceNinja")
    ]
    
    for cmd, description in commands: 
        run_command(cmd, description)

def filter_unique_subdomains(input_file, output_file):
    """Filter unique subdomains from the input file."""
    run_command(f"sort -u {input_file} > {output_file}", f"Filtering unique subdomains from {input_file}")

def merge_subdomains():
    """Combine all the files and delete the old ones."""
    print("\033[34mINFO:\033[0m \033[31m All subdomains are being merged....\033[0m")
    run_command("cat crt certspotter webarchive jldc hackertarget alienvault subdomaincenter rapiddns subfinder assetfinder virustotal securitytrails traceninja | sort -u > subdomain.txt", "Çeşitli kaynaklardan subdomain'leri birleştiriyor")
    
    # Filter unique subdomains
    filter_unique_subdomains("subdomain.txt", "subdomains.txt")
    
    # subdomain.txt dosyasını sil
    if os.path.exists("subdomain.txt"):
        print("\033[34mINFO:\033[0m \033[31m subdomain.txt being deleted...\033[0m")
        run_command("rm subdomain.txt", "Deleting subdomain.txt")
    
    # Delete other output files
    files_to_remove = ["crt", "certspotter", "webarchive", "jldc", "hackertarget", "alienvault", "subdomaincenter", "rapiddns", "subfinder", "assetfinder", "virustotal", "securitytrails", "traceninja"]
    for file in files_to_remove:
        if os.path.exists(file):
            print(f"\033[34mINFO:\033[0m \033[31m {file} being deleted...\033[0m")
            run_command(f"rm {file}", f"{file} being deleted...")
        else:
            print(f"\033[34mINFO:\033[0m \033[31m {file} not found, skipped deletion.\033[0m")

def run_dnsbruter(domain):
    """Scan the domain's subdomains using DNSBruter."""
    print("\033[34mINFO:\033[0m \033[32m Performing the scan with DNSBruter...\033[0m")
    command = f"dnsbruter -d {domain} -w subdomains-top1million-5000.txt -c 200 -wt 100 -o output-dnsbruter.txt -ws wild.txt"
    run_command(command, "Scan is being conducted with DNSBruter")

if __name__ == "__main__":
    # Print the banner
    print_banner()

    parser = argparse.ArgumentParser(description="Subdomain Enumeration Script")
    parser.add_argument("-d", "--domain", help="domain to enumerate subdomains for", required=True)
    args = parser.parse_args()

    domain = args.domain

    # Gather the subdomains
    gather_subdomains(domain)

    # Combine all subdomains
    merge_subdomains()

    # Perform a scan with Subfinder
    run_subfinder()
