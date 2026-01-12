# Buffer Overflow Practice Server
# Intentionally vulnerable C server for binary exploitation

FROM ubuntu:20.04

LABEL maintainer="CyberLab"
LABEL description="Custom vulnerable server for buffer overflow practice"
LABEL lab.category="exploitation"
LABEL lab.difficulty="advanced"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    gcc \
    gdb \
    netcat \
    socat \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy vulnerable source code
COPY vuln-server.c /app/
COPY stack-vuln.c /app/
COPY format-vuln.c /app/

# Compile with vulnerable settings (no protections)
# -fno-stack-protector: Disable stack canaries
# -z execstack: Make stack executable
# -no-pie: Disable PIE (Position Independent Executable)
RUN gcc -o vuln-server vuln-server.c -fno-stack-protector -z execstack -no-pie -g
RUN gcc -o stack-vuln stack-vuln.c -fno-stack-protector -z execstack -no-pie -g
RUN gcc -o format-vuln format-vuln.c -fno-stack-protector -z execstack -no-pie -g

# Disable ASLR (Address Space Layout Randomization) at runtime
RUN echo 0 > /proc/sys/kernel/randomize_va_space || true

# Create flag
RUN echo "FLAG{buff3r_0v3rfl0w_m4st3r}" > /app/flag.txt
RUN chmod 644 /app/flag.txt

EXPOSE 9999 9998 9997

# Run multiple vulnerable services
CMD socat TCP-LISTEN:9999,reuseaddr,fork EXEC:/app/vuln-server & \
    socat TCP-LISTEN:9998,reuseaddr,fork EXEC:/app/stack-vuln & \
    socat TCP-LISTEN:9997,reuseaddr,fork EXEC:/app/format-vuln & \
    tail -f /dev/null
