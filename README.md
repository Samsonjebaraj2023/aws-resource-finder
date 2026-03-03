# AWS Resource Finder

AWS Resource Finder is a lightweight web application that allows you to quickly locate and retrieve details about various AWS resources across 20 different AWS regions simultaneously. 

Instead of manually switching between regions in the AWS Console to figure out where a specific resource (like an EC2 instance, VPC, or Security Group) is located, you can simply paste the resource IDs into this tool, and it will find them for you in parallel.

## Features

- **Multi-Region Search:** Automatically searches across 20 AWS regions concurrently to locate your resources fast.
- **Bulk Search:** Look up to 20 different resource IDs at the same time.
- **Auto-Detection:** Automatically detects the resource type based on the ID prefix (e.g., `i-` for EC2, `vpc-` for VPC).
- **Comprehensive Support:** Supports a wide range of AWS resources including:
  - VPCs (`vpc-`)
  - Subnets (`subnet-`)
  - Security Groups (`sg-`)
  - EC2 Instances (`i-`)
  - EBS Volumes (`vol-`)
  - Snapshots (`snap-`)
  - AMIs (`ami-`)
  - NAT Gateways (`nat-`)
  - Internet Gateways (`igw-`)
  - Route Tables (`rtb-`)
  - Network Interfaces / ENIs (`eni-`)
  - Elastic IPs (`eipalloc-`)
  - S3 Buckets (`s3://`)
- **JSON Export:** Easily export your search results to a JSON file for reporting or further programmatic use.
- **Modern UI:** A sleek, dark-themed, responsive user interface with progress tracking and detailed resource attribute display.

## Prerequisites

- **Python 3.x**
- **pip** (Python package installer)

## Installation

1. Clone or download this repository.
2. (Optional but recommended) Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```
3. Install the required dependencies:
   ```bash
   pip install flask flask-cors boto3
   ```
   
## Usage

1. **Start the Backend Server:**
   Run the Flask application from your terminal:
   ```bash
   python app.py
   ```
   The backend will start running on `http://localhost:5002`.

2. **Open the Frontend:**
   Simply open the `index.html` file in your preferred web browser.

3. **Connect to AWS:**
   Provide your AWS credentials (Access Key ID, Secret Access Key, and optionally a Session Token) in the login card to authenticate. The app uses these temporarily to make AWS API calls but does not store them.

4. **Search:**
   Enter the IDs of the resources you want to find (one per line or comma-separated), and click **Search All Resources**.

## Architecture & Security

- **Backend:** A Python Flask application (`app.py`) that uses `boto3` to communicate with the AWS API. It relies on Python's `concurrent.futures.ThreadPoolExecutor` to perform blazing-fast lookups across multiple regions simultaneously.
- **Frontend:** A pure HTML/CSS/JavaScript interface (`index.html`) that communicates with the Flask backend via RESTful APIs.
- **Security:** Credentials are sent to the backend to create short-lived boto3 sessions per request. They are not persistently saved on the server. Make sure to run this application locally or secure it appropriately if hosting it remotely.
