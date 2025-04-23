# Playbook: Threat Model Playbook - Amazon RDS, SQL Server (PII) via VPC

Linkedin: https://www.linkedin.com/in/mr-lopeza/

Objective: 
* **Understand: Recognize the critical security risks posed by hardcoded secrets.
* **Identify: Learn effective methods and tools to detect secrets in code and commit history.
* **Secure: Implement secure patterns (environment variables, secrets managers, etc.) for handling secrets, replacing hardcoding.
* **Prevent: Adopt strategies (automated checks, training, policies) to stop secrets from being hardcoded in the future.
* **Remediate: Follow clear steps to address discovered secrets, including rotation and cleanup.

Vulnerability Details: SQL Injection (CWE-89)
File: app.py

Function: get_product_vulnerable

Route: /product_vulnerable/<product_id>

Description:
The application constructs an SQL query by directly embedding user-controlled input (product_id from the URL) into the query string using Python's f-string formatting. No validation, sanitization, or parameterized queries are used, allowing attackers to manipulate the SQL command.

Vulnerable Code Snippet (app.py):

@app.route('/product_vulnerable/<product_id>')
def get_product_vulnerable(product_id):
    # ... (database connection setup) ...
    cursor = db_conn.cursor()

    # !!! VULNERABLE LINE !!!
    # User input 'product_id' is directly placed into the SQL query string.
    query = f"SELECT id, name, price FROM products WHERE id = {product_id}"
    # !!! END VULNERABLE LINE !!!

    try:
        app.logger.info(f"Executing vulnerable query: {query}")
        cursor.execute(query) # The manipulated query is executed
        # ... (rest of the function) ...

Exploitation Examples:

Bypass: Accessing /product_vulnerable/1%20OR%201=1 results in the query ... WHERE id = 1 OR 1=1, potentially returning unintended data.

Data Extraction: Using UNION SELECT payloads like /product_vulnerable/0%20UNION%20SELECT... can extract data from other tables/columns.

Impact:

Confidentiality Loss: Reading sensitive data.

Integrity Loss: Modifying or deleting data.

Availability Loss: Denial of Service by crashing the database or deleting critical data.

Detection Methods
SAST Scan (Bandit):

Running bandit app.py identified the vulnerability:

>> Issue: [B608:hardcoded_sql_expressions] Possible SQL injection vector through string formatting.
   Severity: Medium   Confidence: Medium
   Location: app.py:49:8 # Line number may vary
   49         query = f"SELECT id, name, price FROM products WHERE id = {product_id}"

Bandit correctly flagged the direct use of f-string formatting with user input in an SQL context.

Manual Code Review:

Confirmed that product_id originates from user input (URL path).

Traced the data flow directly into the query f-string without any sanitization or parameterization.

Identified the lack of secure handling as the root cause.

The Fix: Parameterized Queries
Secure Coding Practice Applied: Parameterized Queries (Prepared Statements).

File: app_fixed.py

Function: get_product_secure

Explanation:
The vulnerability is fixed by using parameterized queries. This involves:

Defining the SQL query with placeholders (?) instead of directly inserting user data.

Passing the user input (product_id) as a separate argument to the cursor.execute() method.

The database driver (sqlite3) then safely handles the user data, ensuring it's treated only as data and not as executable SQL code. This separation prevents injection attacks.

Fixed Code Snippet (app_fixed.py):

@app.route('/product_secure/<product_id>')
def get_product_secure(product_id):
    # ... (database connection setup) ...
    cursor = db_conn.cursor()

    # !!! SECURE CODE !!!
    # Define the SQL query using a placeholder (?)
    query = "SELECT id, name, price FROM products WHERE id = ?"
    # !!! END SECURE CODE !!!

    try:
        # Execute using the placeholder and passing data separately
        cursor.execute(query, (product_id,)) # Parameterized execution
        product = cursor.fetchone()
        # ... (rest of the function) ...

Verification of Fix
SAST Scan (Bandit): Running bandit app_fixed.py no longer reports the B608 SQLi finding for the get_product_secure function.

Manual Review: Confirmed the correct use of placeholders and separate parameters in get_product_secure.

Functional Testing: Accessing the secure endpoint /product_secure/1%20OR%201=1 resulted in a "Product not found" error (or similar safe failure), not the successful bypass seen with the vulnerable endpoint.

How to Run
Prerequisites: Python 3 and Flask (pip install Flask).

Vulnerable Version:

Save the vulnerable code as app.py.

Run: python app.py

Access: http://127.0.0.1:5000/product_vulnerable/1

Try injecting: http://127.0.0.1:5000/product_vulnerable/1%20OR%201=1

Fixed Version:

Save the fixed code as app_fixed.py.

Run: python app_fixed.py

Access secure: http://127.0.0.1:5000/product_secure/1

Attempt injection (should fail safely): http://127.0.0.1:5000/product_secure/1%20OR%201=1
