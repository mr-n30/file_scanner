#!/usr/bin/env python3
import requests, argparse, json, sys, yaml

# Parse argv
parser = argparse.ArgumentParser(
    prog="File Scanner",
    description="Scan a file for anything malicious using VirusTotal, OTX, and Falcon Sandbox API and see whether the file is malicious or not",
    usage=f"{sys.argv[0]} [-h] -k <YAML_FILE> <FILE_TO_SCAN>",
)
parser.add_argument(
    "filename",
    help='Your file to scan. If value is "generate_yaml_template" a YAML template file will be generated.',
    metavar="file",
)
parser.add_argument(
    "-k",
    "--api-keys",
    help="YAML file containing your API keys. Use generate_yaml_template as filename argument to generate a template YAML file.",
    required=True,
    metavar="file",
)

# Global variables
args = parser.parse_args()
filename = args.filename
api_keys = args.api_keys

providers = []
indicators = {"indicators": []}
vt_api_key = None
fs_api_key = None
otx_api_key = None

# Uploads a file to OTX and scans it
def otx(api_key):
    url = "https://otx.alienvault.com/api/v1/indicators/submit_file"
    headers = {"X-OTX-API-KEY": api_key}
    with open(filename, "r") as f:
        try:
            # Submit the file to OTX and parse the results
            upload_url = requests.post(url, headers=headers, files={"file": f})
            file_hash = upload_url.json()["sha256"]
            results = requests.get(
                f"https://otx.alienvault.com/api/v1/indicator/file/{file_hash}/analysis"
            )

            # Build results for: OTX
            provider = "OTX"
            otx_type = "file"
            is_malicious = (
                "not malicious" if not results.json()["malware"] else "malicious"
            )
            providers.append(
                {
                    "provider": provider,
                    "verdict": is_malicious,
                    "score": None,
                    "type": otx_type,
                }
            )
        except Exception as e:
            print(f"ERROR: {e}")


# Uploads a file to VirusTotal and scans it
def virustotal(api_key):
    url = "https://www.virustotal.com/api/v3/files"

    headers = {
        "X-Apikey": api_key,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",  # VT requires a valid UA
    }

    with open(filename, "r") as f:
        try:
            # Submit the file to VirusTotal and parse the results
            upload_url = requests.post(url, headers=headers, files={"file": f})
            analysis_url = requests.get(
                upload_url.json()["data"]["links"]["self"], headers=headers
            )
            results_json = requests.get(
                f'{url}/{analysis_url.json()["meta"]["file_info"]["sha256"]}',
                headers=headers,
            ).json()

            # Build results for: VirusTotal
            provider = "VirusTotal"
            vt_type = results_json["data"]["type"]
            score = results_json["data"]["attributes"]["reputation"]
            is_malicious = (
                "not malicious"
                if results_json["data"]["attributes"]["total_votes"]["malicious"] == 0
                else "malicious"
            )
            providers.append(
                {
                    "provider": provider,
                    "verdict": is_malicious,
                    "score": score,
                    "type": vt_type,
                }
            )
        except Exception as e:
            print(f"ERROR: {e}")


# Uploads a file to Falcon Sandbox and scans it
def falcon_sandbox(api_key):
    url = "https://www.hybrid-analysis.com/api/v2/submit/file"

    headers = {
        "api-key": api_key,
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:102.0) Gecko/20100101 Firefox/102.0",  # FS requires a valid UA
    }

    with open(filename, "r") as f:
        try:
            # Submit the file to Falcon Sandbox and parse the results
            upload_url = requests.post(
                url, headers=headers, files={"file": f}, data={"environment_id": 310}
            )
            sha256 = upload_url.json()["sha256"]
            results_json = requests.get(
                f"https://www.hybrid-analysis.com/api/v2/report/{sha256}:310/summary",
                headers=headers,
            ).json()

            # Build results for: Falcon Sandbox
            provider = "Falcon Sandbox"
            fs_type = results_json["type"]
            score = results_json["threat_score"]
            is_malicious = "not malicious" if score == None else "malicious"
            providers.append(
                {
                    "provider": provider,
                    "verdict": is_malicious,
                    "score": score,
                    "type": fs_type,
                }
            )
            indicators["indicators"].append(providers)

            # Show the results
            print(json.dumps(indicators, indent=4))
        except Exception as e:
            print(f"ERROR: {e}")


if __name__ == "__main__":
    if filename == "generate_yaml_template":
        template = "virustotal:\n  - <API_KEY>\notx:\n  - <API_KEY>\nfalcon_sandbox:\n  - <API_KEY>\n"
        with open("keys.yaml", "w") as f:
            f.write(template)
            print("[+] Template file created to: ./keys.yaml")
            sys.exit()

    with open(api_keys, "r") as f:
        # Retrieve keys from file
        keys = yaml.safe_load(f)

        # Scan the file using API's
        otx(keys["otx"][0])
        virustotal(keys["virustotal"][0])
        falcon_sandbox(keys["falcon_sandbox"][0])
