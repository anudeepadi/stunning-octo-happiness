# Vulnerable PostgreSQL Database
# Weak credentials, plaintext passwords, injectable queries

FROM postgres:12

LABEL maintainer="CyberLab"
LABEL description="PostgreSQL with intentional vulnerabilities"
LABEL lab.category="database"
LABEL lab.difficulty="intermediate"

# Copy initialization script
COPY init.sql /docker-entrypoint-initdb.d/

# Expose PostgreSQL port
EXPOSE 5432

ENV POSTGRES_PASSWORD=postgres
ENV POSTGRES_USER=postgres
ENV POSTGRES_DB=vulnerable_db
