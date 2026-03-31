-- MySQL init script for RustNmap test range
-- Creates test databases, users, and sample data

-- Create test database
CREATE DATABASE IF NOT EXISTS testdb;
USE testdb;

-- Create sample table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(100),
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert sample data
INSERT INTO users (username, email) VALUES
    ('admin', 'admin@rustnmap.test'),
    ('testuser', 'testuser@rustnmap.test'),
    ('guest', 'guest@rustnmap.test');

-- Create another table for version detection
CREATE TABLE IF NOT EXISTS products (
    id INT AUTO_INCREMENT PRIMARY KEY,
    name VARCHAR(100),
    price DECIMAL(10,2)
);

INSERT INTO products (name, price) VALUES
    ('Test Product 1', 9.99),
    ('Test Product 2', 19.99);

-- Create user with empty password for mysql-empty-password testing
CREATE USER IF NOT EXISTS 'emptyuser'@'%' IDENTIFIED BY '';
GRANT SELECT ON testdb.* TO 'emptyuser'@'%';

-- Create limited user
CREATE USER IF NOT EXISTS 'limited'@'%' IDENTIFIED BY 'limited123';
GRANT SELECT ON testdb.* TO 'limited'@'%';

-- Grant test user full access
CREATE USER IF NOT EXISTS 'testuser'@'%' IDENTIFIED BY 'test123';
GRANT ALL PRIVILEGES ON *.* TO 'testuser'@'%';

FLUSH PRIVILEGES;
