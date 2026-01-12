-- =============================================================================
-- Vulnerable PostgreSQL Database Setup
-- FOR EDUCATIONAL PURPOSES ONLY
-- =============================================================================

-- Create vulnerable database
CREATE DATABASE vulnerable_db;
\c vulnerable_db;

-- =============================================================================
-- WEAK USERS
-- =============================================================================

CREATE USER admin_user WITH PASSWORD 'admin123' SUPERUSER;
CREATE USER webapp WITH PASSWORD 'webapp';
CREATE USER readonly WITH PASSWORD 'password';

GRANT ALL PRIVILEGES ON DATABASE vulnerable_db TO admin_user;
GRANT ALL PRIVILEGES ON DATABASE vulnerable_db TO webapp;
GRANT CONNECT ON DATABASE vulnerable_db TO readonly;

-- =============================================================================
-- USERS TABLE (plaintext passwords)
-- =============================================================================

CREATE TABLE users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    ssn VARCHAR(11),  -- Social Security Number (sensitive!)
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO users (username, password, email, role, ssn) VALUES
('admin', 'SuperSecretPassword123!', 'admin@cyberlab.local', 'admin', '123-45-6789'),
('john', 'password123', 'john@cyberlab.local', 'user', '234-56-7890'),
('jane', 'qwerty', 'jane@cyberlab.local', 'user', '345-67-8901'),
('bob', 'letmein', 'bob@cyberlab.local', 'moderator', '456-78-9012');

-- =============================================================================
-- EMPLOYEES TABLE (HR data extraction practice)
-- =============================================================================

CREATE TABLE employees (
    id SERIAL PRIMARY KEY,
    first_name VARCHAR(50),
    last_name VARCHAR(50),
    email VARCHAR(100),
    salary DECIMAL(10, 2),
    department VARCHAR(50),
    manager_id INT,
    hire_date DATE
);

INSERT INTO employees (first_name, last_name, email, salary, department, manager_id, hire_date) VALUES
('John', 'Smith', 'john.smith@company.com', 85000.00, 'Engineering', NULL, '2020-01-15'),
('Jane', 'Doe', 'jane.doe@company.com', 95000.00, 'Engineering', 1, '2020-03-20'),
('Bob', 'Wilson', 'bob.wilson@company.com', 75000.00, 'Marketing', 1, '2021-06-10'),
('Alice', 'Brown', 'alice.brown@company.com', 120000.00, 'Management', NULL, '2019-08-01'),
('Charlie', 'Davis', 'charlie.davis@company.com', 65000.00, 'Support', 4, '2022-02-28');

-- =============================================================================
-- API KEYS TABLE (secrets extraction)
-- =============================================================================

CREATE TABLE api_keys (
    id SERIAL PRIMARY KEY,
    service_name VARCHAR(50),
    api_key VARCHAR(100),
    api_secret VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO api_keys (service_name, api_key, api_secret) VALUES
('AWS', 'AKIA_FAKE_EXAMPLE_KEY_12345', 'fake_secret_key_for_educational_use'),
('Stripe', 'sk_fake_educational_example_key', 'whsec_fake_example'),
('SendGrid', 'SG_fake_educational_key_here', 'sendgrid_fake_secret'),
('Twilio', 'AC_fake_educational_sid_example', 'fake_auth_token');

-- =============================================================================
-- CTF FLAGS
-- =============================================================================

CREATE TABLE flags (
    id SERIAL PRIMARY KEY,
    challenge_name VARCHAR(50),
    flag_value VARCHAR(100),
    points INT
);

INSERT INTO flags (challenge_name, flag_value, points) VALUES
('postgres_injection', 'FLAG{p0stgr3s_pwn3d}', 150),
('data_exfiltration', 'FLAG{hr_d4t4_l34k3d}', 200),
('api_key_theft', 'FLAG{cl0ud_cr3ds_st0l3n}', 250);

-- Grant permissions
GRANT SELECT, INSERT, UPDATE, DELETE ON ALL TABLES IN SCHEMA public TO webapp;
GRANT SELECT ON ALL TABLES IN SCHEMA public TO readonly;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO webapp;
