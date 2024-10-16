# Use the official Rust image as the build environment
FROM rust:1.70 as builder

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock ./

# Copy the source code
COPY src ./src

# Build the project
RUN cargo build --release

# Use a minimal base image for the final image
FROM debian:buster-slim

# Set the working directory inside the container
WORKDIR /usr/src/app

# Copy the compiled binary from the build environment
COPY --from=builder /usr/src/app/target/release/RedunX .

# Expose the port the application runs on
EXPOSE 3030

# Set the entrypoint to the compiled binary
CMD ["./RedunX"]