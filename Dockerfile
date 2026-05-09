FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    g++ cmake make libboost-all-dev libssl-dev python3 git \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy C++ source and build
COPY bifrost/ ./bifrost/
RUN cmake -S bifrost -B build && cmake --build build --target bifrost
RUN cp build/bifrost ./bifrost-bin

# Copy the single Python server file
COPY bifrost_server.py .

ENV BIFROST_BIN=/app/bifrost-bin
ENV SECRET_KEY_PATH=/app/secret.key

EXPOSE 8000
CMD ["python3", "bifrost_server.py"]