# Use the official Rust image as the base image
FROM rust:1.70

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock ./

# Copy the source code
COPY src ./src

# Expose the port the application runs on
EXPOSE 5678

# Run the application
CMD ["cargo", "run"]