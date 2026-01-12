-- =============================================================================
-- Vulnerable MySQL Database Setup
-- FOR EDUCATIONAL PURPOSES ONLY - SQL Injection Practice
-- =============================================================================

-- Create vulnerable database
CREATE DATABASE IF NOT EXISTS vulnerable_db;
USE vulnerable_db;

-- =============================================================================
-- WEAK USERS (for credential attacks)
-- =============================================================================

-- User with admin privileges and weak password
CREATE USER IF NOT EXISTS 'admin'@'%' IDENTIFIED BY 'admin123';
GRANT ALL PRIVILEGES ON *.* TO 'admin'@'%' WITH GRANT OPTION;

-- Web application user with FILE privilege (allows file reading via SQLi)
CREATE USER IF NOT EXISTS 'webapp'@'%' IDENTIFIED BY 'webapp';
GRANT ALL PRIVILEGES ON vulnerable_db.* TO 'webapp'@'%';
GRANT FILE ON *.* TO 'webapp'@'%';

-- Read-only user
CREATE USER IF NOT EXISTS 'readonly'@'%' IDENTIFIED BY 'password';
GRANT SELECT ON vulnerable_db.* TO 'readonly'@'%';

FLUSH PRIVILEGES;

-- =============================================================================
-- USERS TABLE (plaintext passwords - vulnerability!)
-- =============================================================================

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,  -- Stored in PLAINTEXT!
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    last_login TIMESTAMP NULL,
    is_active BOOLEAN DEFAULT TRUE
);

-- Insert vulnerable user data
INSERT INTO users (username, password, email, role) VALUES
('admin', 'SuperSecretPassword123!', 'admin@cyberlab.local', 'admin'),
('john', 'password123', 'john@cyberlab.local', 'user'),
('jane', 'qwerty', 'jane@cyberlab.local', 'user'),
('bob', 'letmein', 'bob@cyberlab.local', 'moderator'),
('alice', '123456', 'alice@cyberlab.local', 'user'),
('charlie', 'password', 'charlie@cyberlab.local', 'user'),
('david', 'iloveyou', 'david@cyberlab.local', 'user'),
('eve', 'welcome', 'eve@cyberlab.local', 'user'),
('frank', 'monkey', 'frank@cyberlab.local', 'user'),
('grace', 'dragon', 'grace@cyberlab.local', 'admin');

-- =============================================================================
-- CREDIT CARDS TABLE (sensitive unencrypted data)
-- =============================================================================

CREATE TABLE IF NOT EXISTS credit_cards (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    card_number VARCHAR(20),      -- UNENCRYPTED!
    cvv VARCHAR(4),               -- CVV stored in plaintext!
    expiry_date DATE,
    card_holder VARCHAR(100),
    billing_address TEXT,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

INSERT INTO credit_cards (user_id, card_number, cvv, expiry_date, card_holder) VALUES
(1, '4111111111111111', '123', '2026-12-01', 'Admin User'),
(2, '5500000000000004', '456', '2025-06-01', 'John Doe'),
(3, '340000000000009', '7890', '2027-03-15', 'Jane Smith'),
(4, '30000000000004', '321', '2025-09-30', 'Bob Wilson'),
(5, '6011000000000004', '654', '2026-08-20', 'Alice Brown');

-- =============================================================================
-- PRODUCTS TABLE (for e-commerce SQLi scenarios)
-- =============================================================================

CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    description TEXT,
    price DECIMAL(10, 2),
    stock INT DEFAULT 0,
    category VARCHAR(50),
    is_featured BOOLEAN DEFAULT FALSE
);

INSERT INTO products (name, description, price, stock, category, is_featured) VALUES
('Laptop Pro X1', 'High-performance laptop with 16GB RAM', 1299.99, 50, 'Electronics', TRUE),
('Wireless Mouse', 'Ergonomic wireless mouse', 29.99, 200, 'Electronics', FALSE),
('USB-C Hub', '7-in-1 USB-C hub with HDMI', 49.99, 150, 'Accessories', TRUE),
('Mechanical Keyboard', 'RGB mechanical keyboard', 89.99, 100, 'Electronics', FALSE),
('Monitor 27"', '4K IPS monitor', 399.99, 30, 'Electronics', TRUE),
('Webcam HD', '1080p webcam with microphone', 59.99, 80, 'Accessories', FALSE),
('Headphones Pro', 'Noise-canceling wireless headphones', 199.99, 60, 'Audio', TRUE),
('Smart Watch', 'Fitness tracking smartwatch', 249.99, 40, 'Wearables', FALSE);

-- =============================================================================
-- ORDERS TABLE (for data extraction practice)
-- =============================================================================

CREATE TABLE IF NOT EXISTS orders (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    product_id INT,
    quantity INT,
    total_price DECIMAL(10, 2),
    status VARCHAR(20) DEFAULT 'pending',
    shipping_address TEXT,
    order_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id),
    FOREIGN KEY (product_id) REFERENCES products(id)
);

INSERT INTO orders (user_id, product_id, quantity, total_price, status, shipping_address) VALUES
(2, 1, 1, 1299.99, 'shipped', '123 Main St, City, ST 12345'),
(3, 3, 2, 99.98, 'delivered', '456 Oak Ave, Town, ST 67890'),
(4, 7, 1, 199.99, 'pending', '789 Pine Rd, Village, ST 11111'),
(5, 2, 3, 89.97, 'processing', '321 Elm Blvd, Metro, ST 22222');

-- =============================================================================
-- SECRETS TABLE (hidden data for extraction challenges)
-- =============================================================================

CREATE TABLE IF NOT EXISTS secrets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    secret_name VARCHAR(50),
    secret_value VARCHAR(255),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO secrets (secret_name, secret_value) VALUES
('api_key', 'sk-cyberlab-a1b2c3d4e5f6g7h8i9j0'),
('jwt_secret', 'super_secret_jwt_key_do_not_share'),
('admin_password_hash', '$2b$12$LQv3c1yqBWVHxkd0LHAkCOYz6TtxMQJqhN8/X4.aHqvqP.P.P.'),
('database_backup_key', 'AES256-BACKUP-KEY-2024'),
('oauth_client_secret', 'oauth_secret_cyberlab_xyzabc123');

-- =============================================================================
-- CTF FLAGS TABLE (for challenges)
-- =============================================================================

CREATE TABLE IF NOT EXISTS flags (
    id INT AUTO_INCREMENT PRIMARY KEY,
    challenge_name VARCHAR(50),
    flag_value VARCHAR(100),
    difficulty VARCHAR(20),
    points INT,
    hint TEXT
);

INSERT INTO flags (challenge_name, flag_value, difficulty, points, hint) VALUES
('sql_injection_basic', 'FLAG{sql_1nj3ct10n_m4st3r}', 'beginner', 100, 'Try a basic OR 1=1 payload'),
('sql_injection_union', 'FLAG{un10n_b4s3d_pwn3d}', 'intermediate', 200, 'Find the number of columns first'),
('sql_injection_blind', 'FLAG{bl1nd_sql1_t1m3_b4s3d}', 'advanced', 300, 'Use time-based techniques'),
('data_extraction', 'FLAG{s3ns1t1v3_d4t4_3xp0s3d}', 'intermediate', 250, 'Look in the secrets table'),
('privilege_escalation', 'FLAG{r00t_4cc3ss_gr4nt3d}', 'advanced', 400, 'Check user privileges with FILE');

-- =============================================================================
-- VULNERABLE STORED PROCEDURE (command injection)
-- =============================================================================

DELIMITER //
CREATE PROCEDURE IF NOT EXISTS search_products(IN search_term VARCHAR(100))
BEGIN
    -- VULNERABLE: Direct string concatenation
    SET @query = CONCAT('SELECT * FROM products WHERE name LIKE "%', search_term, '%"');
    PREPARE stmt FROM @query;
    EXECUTE stmt;
    DEALLOCATE PREPARE stmt;
END //
DELIMITER ;

-- =============================================================================
-- VIEWS FOR PRACTICE
-- =============================================================================

CREATE OR REPLACE VIEW user_summary AS
SELECT
    u.id,
    u.username,
    u.email,
    u.role,
    COUNT(o.id) as total_orders,
    COALESCE(SUM(o.total_price), 0) as total_spent
FROM users u
LEFT JOIN orders o ON u.id = o.user_id
GROUP BY u.id;

-- =============================================================================
-- AUDIT LOG (for forensics practice)
-- =============================================================================

CREATE TABLE IF NOT EXISTS audit_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    action VARCHAR(50),
    table_name VARCHAR(50),
    user_ip VARCHAR(45),
    query_text TEXT,
    timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Sample audit entries
INSERT INTO audit_log (action, table_name, user_ip, query_text) VALUES
('SELECT', 'users', '192.168.1.100', 'SELECT * FROM users WHERE id = 1'),
('LOGIN_ATTEMPT', 'users', '10.0.0.50', 'Failed login for user: admin'),
('SELECT', 'credit_cards', '192.168.1.100', 'SELECT * FROM credit_cards'),
('UPDATE', 'users', '172.20.5.10', 'UPDATE users SET password = "newpass" WHERE id = 2');

FLUSH PRIVILEGES;
