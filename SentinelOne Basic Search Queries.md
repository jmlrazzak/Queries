**HUNTING QUERIES (they work)**

**User Account Operations**

<ins>Search for Add User
```
ProcessCmd RegExp "net\s+user(?:(?!\s+/add)(?:.|\n))*\s+/add"
```
<ins>Search for Delete User
```
