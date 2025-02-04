# GitHub Scanner

## Overview

GitHub Scanner is a Go-based service that provides two REST APIs to scan a GitHub repository for JSON files and store their contents, and to query stored JSON payloads using key-value filters. This project is designed to be modular, production-ready, and includes unit tests, Docker setup, and Swagger documentation.

## Features

- **Scan API**: Fetches and processes JSON files from a specified GitHub repository.
- **Query API**: Returns JSON payloads matching specified filters.
- **Concurrency**: Processes multiple files in parallel.
- **Error Handling**: Retries failed GitHub API calls.
- **Docker**: Single container setup for the service.
- **Swagger Documentation**: Provides API documentation and testing interface.

## API Endpoints

### Scan API

**Endpoint**: `POST /scan`

**Request Body**:
```json
{
   "repo": "<repo root>",
   "files": ["<filename1>", "<filename2>", …]
}
```

**Description**: Fetches all `.json` files from the specified GitHub path, processes files containing arrays of JSON payloads, and stores each payload with metadata (source file, scan time).

### Query API

**Endpoint**: `POST /query`

**Request Body**:
```json
{
   "filters": {
      "severity": "HIGH"
   }
}
```

**Description**: Returns all payloads matching any one filter key (exact matches). Currently focuses on the `severity` filter.

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

## Setup and Installation

1. **Clone the repository**:
    ```sh
    git clone https://github.com/yourusername/github-scanner.git
    cd github-scanner
    ```

2. **Build the Docker image**:
    ```sh
    docker build -t github-scanner .
    ```

3. **Run the Docker container**:
    ```sh
    docker run -p 8080:8080 github-scanner
    ```

## Swagger Documentation

Swagger documentation is available to provide a detailed interface for the APIs. To access the Swagger UI, navigate to `http://localhost:8080/swagger/index.html` after running the Docker container.

#### Make sure to authorize before using /scan and /query endpoints by clicking ```Authorize``` button and enter ```secret``` as value.

## Running Tests

To run the unit tests, use the following command:
```sh
go test ./...
```

## Deliverables

- **Code**: Modular, production-ready Go code.
- **Unit Tests**: 60%+ coverage for core logic.
- **Docker Setup**: Single Docker container with dependencies.
