# Vulnerable SSH Server
# Weak crypto, default credentials, old SSH version

FROM ubuntu:20.04

LABEL maintainer="CyberLab"
LABEL description="SSH server with weak configuration for attack practice"
LABEL lab.category="service"
LABEL lab.difficulty="intermediate"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Create vulnerable users with weak passwords
RUN useradd -m -s /bin/bash admin && echo "admin:admin" | chpasswd
RUN useradd -m -s /bin/bash user && echo "user:password" | chpasswd
RUN useradd -m -s /bin/bash guest && echo "guest:guest" | chpasswd
RUN useradd -m -s /bin/bash root2 && echo "root2:toor" | chpasswd

# Create SSH directory
RUN mkdir /var/run/sshd

# Configure SSH with weak settings
RUN sed -i 's/#PermitRootLogin prohibit-password/PermitRootLogin yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PasswordAuthentication yes/PasswordAuthentication yes/' /etc/ssh/sshd_config
RUN sed -i 's/#PermitEmptyPasswords no/PermitEmptyPasswords yes/' /etc/ssh/sshd_config

# Add weak ciphers configuration
RUN echo "Ciphers aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc" >> /etc/ssh/sshd_config
RUN echo "MACs hmac-sha1,hmac-md5" >> /etc/ssh/sshd_config
RUN echo "KexAlgorithms diffie-hellman-group1-sha1,diffie-hellman-group14-sha1" >> /etc/ssh/sshd_config

# Create flag file
RUN echo "FLAG{ssh_w34k_cr3ds_pwn3d}" > /root/flag.txt
RUN echo "FLAG{ssh_us3r_4cc3ss}" > /home/admin/flag.txt
RUN chmod 600 /root/flag.txt
RUN chmod 644 /home/admin/flag.txt

# Create interesting files for post-exploitation
RUN echo "DB_PASSWORD=supersecret123" > /home/admin/.env
RUN echo "API_KEY=sk-cyberlab-secret-key" >> /home/admin/.env

EXPOSE 22

CMD ["/usr/sbin/sshd", "-D"]
