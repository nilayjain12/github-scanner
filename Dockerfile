# Use an official Golang image as a build environment
FROM golang:1.23-alpine AS builder

# Enable CGO and install required dependencies
ENV CGO_ENABLED=1 \
    GOOS=linux \
    GOARCH=amd64

# Install required build tools
RUN apk add --no-cache gcc musl-dev libc-dev

# Set the working directory inside the container
WORKDIR /app

# Copy the Go module files and download dependencies
COPY go.mod go.sum ./
RUN go mod tidy

# Copy the entire project, including SQL schema files
COPY . .

# Build the application
RUN go build -o github-scanner ./cmd/main.go

# Use a minimal base image for final deployment
FROM alpine:latest  

# Install SQLite dependencies
RUN apk add --no-cache ca-certificates sqlite

# Set the working directory
WORKDIR /app  # Make sure the working directory is correct

# Copy the compiled binary and necessary files from the build stage
COPY --from=builder /app/github-scanner .
COPY --from=builder /app/.env .env  
COPY --from=builder /app/internal/database/schema internal/database/schema

# Expose the application port
EXPOSE 8080

# Run the application
CMD ["./github-scanner"]
