Put the MySQL JDBC driver jar in this folder.

1. Go to https://dev.mysql.com/downloads/connector/j/
2. Choose "Platform Independent" and download the ZIP.
3. Open the ZIP and copy  mysql-connector-j-<version>.jar  into this lib folder.

The build_and_run.ps1 script adds lib/* to the Java classpath automatically.
