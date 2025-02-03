FROM golang:1.20-alpine

# Set environment variables for Go module support and cross-compilation
ENV GO111MODULE=on \
    CGO_ENABLED=0 \  
    GOOS=linux \     
    GOARCH=amd64     

# Create and set the working directory inside the container
WORKDIR /app

# Verify if go.mod and go.sum exist before copying to avoid build failures
# RUN if [ -f go.mod ] && [ -f go.sum ]; then echo "go.mod and go.sum found, proceeding with copy."; else echo "go.mod or go.sum missing, aborting build." && exit 1; fi

# Copy go.mod and go.sum to leverage Docker cache for dependencies
COPY go.mod go.sum ./

# Download Go module dependencies
RUN go mod download

# Copy the entire project source code into the container
COPY . .

# Build the Go application
RUN go build -o github-scanner ./cmd/main.go

# Expose the application's port to the host
EXPOSE 8080

# Add a health check script to ensure dependencies are initialized before the app runs
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
  CMD wget --quiet --tries=1 --spider http://localhost:8080/health || exit 1

# Run the compiled application
CMD ["./github-scanner"]
