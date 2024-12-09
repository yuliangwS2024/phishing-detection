import csv
import requests
from concurrent.futures import ThreadPoolExecutor

# Input and output file paths
input_file = "Filtered_Non_Malicious.csv"
output_file = "Accessible_Non_Malicious.csv"

# Function to check URL accessibility
def check_url_accessibility(url, timeout=5):
    try:
        response = requests.head(url, timeout=timeout)
        if response.status_code == 200:
            return url
    except requests.RequestException:
        pass
    return None

# Function to process a single URL
def process_url(row):
    url = row['url'].strip()
    print(f"Processing URL: {url}")  # Debug logging
    accessible_url = check_url_accessibility(url)
    print(f"Accessible: {accessible_url}")  # Debug logging
    return accessible_url

# Main function
def main():
    accessible_urls = []

    # Read URLs from the input file and filter based on 'is_malicious'
    try:
        with open(input_file, "r") as infile:
            reader = csv.DictReader(infile)  # Use DictReader for column-based access
            filtered_rows = [row for row in reader if row['is_malicious'].strip() == '0.0']
    except FileNotFoundError:
        print(f"Error: Input file '{input_file}' not found.")
        return
    except Exception as e:
        print(f"Error reading input file: {e}")
        return

    # Debugging: Total rows after filtering
    print(f"Total URLs with is_malicious=0: {len(filtered_rows)}")

    # Limit to the first 5000 rows
    filtered_rows = filtered_rows[:5000]

    if not filtered_rows:
        print("No URLs found with is_malicious=0.")
        return

    # Use ThreadPoolExecutor for multithreaded processing
    with ThreadPoolExecutor(max_workers=10) as executor:
        results = list(executor.map(process_url, filtered_rows))  # Ensure the generator is consumed

    # Filter out None values and collect accessible URLs
    accessible_urls = [url for url in results if url is not None]

    # Write accessible URLs to the output file
    if accessible_urls:
        with open(output_file, "w", newline="") as outfile:
            writer = csv.writer(outfile)
            writer.writerow(["Accessible URL"])
            for url in accessible_urls:
                writer.writerow([url])

        print(f"Accessible URLs saved to {output_file}")
    else:
        print("No accessible URLs found.")

if __name__ == "__main__":
    main()
