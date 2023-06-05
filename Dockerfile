# Start from the official Go image
FROM golang:1.20.4-alpine

# Set the working directory inside the container
WORKDIR /NoSequel-Database

# Copy the Go modules files
COPY go.mod go.sum ./

# Download and install the project dependencies
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go application
RUN go build -o myapp

# Expose a port if your application listens on a specific port
EXPOSE 8080

# Set the entry point for the container
CMD ["./myapp"]