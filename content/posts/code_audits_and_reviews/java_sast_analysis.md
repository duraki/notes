---
title: "Java Source Code Analysis"
---

### Exploitable Java Functions

* **Input Validation Vulnerabilities**: May be identified using the below functions. Additional vulnerabilities may arise due to use user-constructed input, such is XSS, SQLi, Code Execution etc. It's important to check how these user-controlled parameters are used in the application source code. If the application uses validation and sanitization frameworks like *Hibernate Validator*, or *Apache Common Validators*, this can help prevent malicious input from being submitted, and ensures that data is stored in a consistent and secure manner.
  * `request.setParameter(...)`
  * `request.getParameter(...)`
  * `request.getParameterValues(...)`
  * `request.getHeader(...)`
* **HTTP/API Routes & Endpoints**: These notations are used to define HTTP/API endpoints and routes in Java, specifically when using Spring Boot framework, and may expose complex or vulnerable implementation:
  * `@GetMapping`
  * `@PostMapping`
  * `@DeleteMapping`
* **Session Management**: These vulnerabilities occur when session data is not properly protected when sessions are not properly managed. This can lead to attacks like Session Hijacking, or Session Fixation.
  * `class HttpSession`
  * `request.getSession(...);`
  * `session.getAttribute(...);`
* **Cryptographic Security Vulnerabilities**: Can be identified using functions below, which can lead to security weaknesses or flaws in cryptographic algorithms, protocols and implementations.
  * `Cipher.getInstance("DES");` - application is using DES encryption alogirthm, which is considered weak and vulnerable to attacks.
  * `KeyPairGenerator.getInstance("RSA")`
  * `KeyPair.generateKeyPair(...)` - if the application is generating a public-private key pair for encryption uses, the private key must be properly protected and stored securly
  * `new SecureRandom()` - using `SecureRandom` object to generate n-byte key, but `SecureRandom` is not peroperly seeded with random data
* **Database & Dynamic Query Construction**: Verify that prepared statements are used to construct dynamic SQL queries. Prepared statements prevent SQL injection by separating the query structure from the data, making it difficult for attackers to inject malicious code.
  * `class PreparedStatement`
  * `Statement.executeQuery()`
* **Output Encoding**: Ensure that output is properly encoded to prevent XSS attacks. Use methods like `encodeURL()`, `encodeURIComponent()`, and `encodeForHTML()`.
  * `HttpServletResponse.getWriter().write()`
* **File Uploads**: If file uploads are supported, verify that the file content is properly validated and sanitized to prevent malicious file uploads. Ensure that uploaded files are stored in a secure location and that access to them is restricted.
  * `class MultipartHttpServletRequest`: 

### Finding SQL Injection in Java JPA Repositories

JPA Query language may be vulnerable to SQL Injection. See [this link](https://www.adam-bien.com/roller/abien/entry/preventing_injection_in_jpa_query) for details. As long as code uses named placeholders (`:instanceName`), or parameterised placeholders (`?1, ?2, ...`), instead of a custom SQL query with appended parameters, the code is protected against SQL injection.

Lets take the following Java JPA SQL query code:

```java
/**
 * @param id      id
 * @return ...
 */
@Query("select * 
        from TableName
        where id = ?1
        and ...
        and ...");

// ... exec query code ...
```

In the above query code, the `select` query is using proper parameterised (numbered) placeholders in `where` clause. **Such queries are not vulnerable to SQL Injection**. 

If the code looked similar to one shown below:

```java
/**
 * @param id      id
 * @return ...
 */
@Query("select * 
        from TableName
        where id =" + id
       "and ...
        and ...");

// ... exec query code ...
```

Due to code using `"... where id =" + id + " and ..."`, it would appended parameter, or value of `id` which could lead to SQL Injection. **Such queries are vulnerable to SQL Injection**.

