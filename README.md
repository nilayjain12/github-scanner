# GitHub Scanner

## Description
GitHub Scanner is a Go-based service designed to scan a specified GitHub repository for JSON files and store their contents. It provides two REST APIs: one for scanning the repository and another for querying the stored JSON payloads using key-value filters.

## Features
- **Scan API**: Fetches and processes JSON files from a specified GitHub repository.
- **Query API**: Returns stored JSON payloads based on specified filters.

## API Endpoints

### 1. Scan API
**Endpoint**: `POST /scan`

**Request Body**:
```json
{
   "repo": "<repo root>",
   "files": ["<filename1>", "<filename2>", …]
}
```

**Description**: Fetches all `.json` files from the specified GitHub path, processes files containing arrays of JSON payloads, and stores each payload with metadata (source file, scan time).

### 2. Query API
**Endpoint**: `POST /query`

**Request Body**:
```json
{
   "filters": {
      "severity": "HIGH"
   }
}
```

**Description**: Returns all payloads matching any one filter key (exact matches).

**Example Response**:
```json
[
   {
      "id": "CVE-2024-1234",
      "severity": "HIGH",
      "cvss": 8.5,
      "status": "fixed",
      "package_name": "openssl",
      "current_version": "1.1.1t-r0",
      "fixed_version": "1.1.1u-r0",
      "description": "Buffer overflow vulnerability in OpenSSL",
      "published_date": "2024-01-15T00:00:00Z",
      "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-1234",
      "risk_factors": [
         "Remote Code Execution",
         "High CVSS Score",
         "Public Exploit Available"
      ]
   },
   {
      "id": "CVE-2024-8902",
      "severity": "HIGH",
      "cvss": 8.2,
      "status": "fixed",
      "package_name": "openldap",
      "current_version": "2.4.57",
      "fixed_version": "2.4.58",
      "description": "Authentication bypass vulnerability in OpenLDAP",
      "published_date": "2024-01-21T00:00:00Z",
      "link": "https://nvd.nist.gov/vuln/detail/CVE-2024-8902",
      "risk_factors": [
         "Authentication Bypass",
         "High CVSS Score"
      ]
   }
]
```

## Requirements
- **Language**: Go
- **Database**: SQLite
- **Concurrency**: Processes ≥ 3 files in parallel
- **Error Handling**: Retries failed GitHub API calls (2 attempts)
- **Docker**: Single container for the service

## Running the Project

### Prerequisites
- Docker installed on your machine
- Go installed on your machine

### Steps
1. **Clone the repository**:
    ```sh
    git clone https://github.com/nilayjain12/vulnerability_scans.git
    cd github-scanner
    ```

2. **Build and run the Docker container**:
    ```sh
    docker build -t github-scanner .
    docker run -p 8080:8080 github-scanner
    ```

3. **Run the service locally** (without Docker):
    ```sh
    go run main.go
    ```

## Testing the Project

### Unit Tests
Run the unit tests using the following command:
```sh
go test ./...
```

### Manual Testing
1. **Scan API**:
    ```sh
    curl -X POST http://localhost:8080/scan -d '{
       "repo": "https://github.com/velancio/vulnerability_scans",
       "files": ["file1.json", "file2.json"]
    }'
    ```

2. **Query API**:
    ```sh
    curl -X POST http://localhost:8080/query -d '{
       "filters": {
          "severity": "HIGH"
       }
    }'
    ```