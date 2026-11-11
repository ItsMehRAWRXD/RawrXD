#!/usr/bin/env python3
#=============================================================================
# upload-to-dashboard.py
# Uploads measurement results to dashboard API
#=============================================================================

import argparse
import json
import sys
import urllib.request
import urllib.error
from pathlib import Path
from datetime import datetime


def upload_metrics(api_url: str, data_file: str) -> bool:
    """Upload metrics to dashboard API"""
    
    # Load measurement data
    data_path = Path(data_file)
    if not data_path.exists():
        print(f"Error: Data file not found: {data_file}", file=sys.stderr)
        return False
    
    with open(data_path, 'r') as f:
        data = json.load(f)
    
    # Prepare request
    url = f"{api_url.rstrip('/')}/api/metrics"
    headers = {
        'Content-Type': 'application/json',
        'User-Agent': 'RawrXD-Measurement-Upload/1.0'
    }
    
    # Add timestamp if not present
    if 'timestamp' not in data:
        data['timestamp'] = datetime.now().isoformat()
    
    # Send request
    try:
        req = urllib.request.Request(
            url,
            data=json.dumps(data).encode('utf-8'),
            headers=headers,
            method='POST'
        )
        
        with urllib.request.urlopen(req, timeout=30) as response:
            if response.status == 200:
                print(f"✓ Successfully uploaded metrics to {url}")
                return True
            else:
                print(f"✗ Upload failed with status {response.status}", file=sys.stderr)
                return False
                
    except urllib.error.HTTPError as e:
        print(f"✗ HTTP error {e.code}: {e.reason}", file=sys.stderr)
        return False
    except urllib.error.URLError as e:
        print(f"✗ URL error: {e.reason}", file=sys.stderr)
        return False
    except Exception as e:
        print(f"✗ Error: {e}", file=sys.stderr)
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Upload measurement results to dashboard'
    )
    parser.add_argument(
        '--url', '-u',
        required=True,
        help='Dashboard API URL (e.g., http://localhost:8080)'
    )
    parser.add_argument(
        '--file', '-f',
        required=True,
        help='Path to measurement JSON file'
    )
    parser.add_argument(
        '--dry-run', '-n',
        action='store_true',
        help='Validate file without uploading'
    )
    
    args = parser.parse_args()
    
    # Validate file
    data_path = Path(args.file)
    if not data_path.exists():
        print(f"Error: File not found: {args.file}", file=sys.stderr)
        sys.exit(1)
    
    try:
        with open(data_path, 'r') as f:
            data = json.load(f)
        print(f"✓ Valid JSON: {args.file}")
        print(f"  Metrics: {list(data.get('metrics', {}).keys())}")
    except json.JSONDecodeError as e:
        print(f"✗ Invalid JSON: {e}", file=sys.stderr)
        sys.exit(1)
    
    if args.dry_run:
        print("Dry run - skipping upload")
        sys.exit(0)
    
    # Upload
    success = upload_metrics(args.url, args.file)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
