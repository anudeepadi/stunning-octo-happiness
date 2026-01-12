# Vulnerable FTP Server
# Anonymous access, directory traversal, weak authentication

FROM ubuntu:20.04

LABEL maintainer="CyberLab"
LABEL description="FTP server with anonymous access and weak security"
LABEL lab.category="service"
LABEL lab.difficulty="beginner"

ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y \
    vsftpd \
    && rm -rf /var/lib/apt/lists/*

# Create FTP user with weak password
RUN useradd -m -s /bin/bash ftpuser && echo "ftpuser:ftp123" | chpasswd

# Create FTP directories
RUN mkdir -p /var/ftp/pub
RUN mkdir -p /var/ftp/private
RUN mkdir -p /home/ftpuser/uploads

# Create flag and sensitive files
RUN echo "FLAG{ftp_4n0nym0us_4cc3ss}" > /var/ftp/pub/flag.txt
RUN echo "FLAG{ftp_pr1v4t3_d4t4}" > /var/ftp/private/secret_flag.txt
RUN echo "admin:SuperSecretPass123" > /var/ftp/private/credentials.txt
RUN echo "Database backup - DO NOT SHARE" > /var/ftp/private/backup.sql

# Set permissions
RUN chmod 755 /var/ftp/pub
RUN chmod 755 /var/ftp/private
RUN chown -R ftp:ftp /var/ftp
RUN chown -R ftpuser:ftpuser /home/ftpuser

# Configure vsftpd for vulnerable operation
RUN echo "listen=YES" > /etc/vsftpd.conf
RUN echo "listen_ipv6=NO" >> /etc/vsftpd.conf
RUN echo "anonymous_enable=YES" >> /etc/vsftpd.conf
RUN echo "local_enable=YES" >> /etc/vsftpd.conf
RUN echo "write_enable=YES" >> /etc/vsftpd.conf
RUN echo "anon_upload_enable=YES" >> /etc/vsftpd.conf
RUN echo "anon_mkdir_write_enable=YES" >> /etc/vsftpd.conf
RUN echo "anon_root=/var/ftp" >> /etc/vsftpd.conf
RUN echo "no_anon_password=YES" >> /etc/vsftpd.conf
RUN echo "hide_ids=NO" >> /etc/vsftpd.conf
RUN echo "pasv_enable=YES" >> /etc/vsftpd.conf
RUN echo "pasv_min_port=30000" >> /etc/vsftpd.conf
RUN echo "pasv_max_port=30009" >> /etc/vsftpd.conf
RUN echo "pasv_address=172.20.4.11" >> /etc/vsftpd.conf
RUN echo "seccomp_sandbox=NO" >> /etc/vsftpd.conf

EXPOSE 21 30000-30009

CMD ["/usr/sbin/vsftpd", "/etc/vsftpd.conf"]
