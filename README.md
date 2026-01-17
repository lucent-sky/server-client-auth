# server‑client‑auth

## Overview

`server‑client‑auth` is a simple authentication system implemented in C. It demonstrates a minimal server and client that authenticate users based on a stored password and salt. The system reads user credentials from a simple flat file (`user_db.txt`), combines a private password with a per‑user salt, and hashes the result to protect against rainbow table attacks. :contentReference[oaicite:0]{index=0}

This project is intended for educational purposes or as a starting point for a lightweight, C‑based authentication mechanism.

## Features

- Simple server‑client authentication written in portable C
- Stores users with salts to improve security against precomputed hash attacks
- Uses hashing to protect stored passwords
- Includes a minimal demonstration database (`user_db.txt`) with user entries

## Project Structure

At a high level, the repository contains:

- LICENSE
- Makefile
- client.c
- server.c
- common.h
- crypto_utils.c
- crypto_utils.h
- user_db.txt


The server.c and client.c files implement the basic server and client, crypto_utils.* contain hashing support and utility functions, and common.h holds shared definitions.

## Building

You can build both the server and client from the included Makefile, or manually:

```
gcc -o server server.c crypto_utils.c
gcc -o client client.c crypto_utils.c
```

# Usage

## Setting up the User Database

The user_db.txt file contains user entries in a simple format:
```
username:salt:password
```

New users can be added by any admin account.  The uploaded user_db.txt is propagated with 2 users, an admin and a normal user, for reference.  In order to use the program, **you must delete the contents of the user_db.txt file or the file entirely** (a new one will be automatically generated if it is not found).

## Running the Server and Client

Once the program is made, run the following commands in the CLI:
```
./server [port #]

./client [ip] [server port #]
```
You can then log in and use the system.

## Security Considerations

- This is a hobby project to showcase knowledge of basic authentication principles and security. It is not production‑ready.

- Passwords and salts are stored in a flat text file, rather than a proper key-value storage or database.

- Hashing algorithms should be chosen carefully for resistance against modern attacks.

- Transport security (TLS/SSL) is not implemented here, as I've only used this on the same computer, rather than over a network.  Using this over a network opens up potential vulnerabilities.

## License

This project is licensed under the GNU Affero General Public License v3.0 (AGPL‑3.0).

Users must comply with the terms of the AGPL when using, modifying, or redistributing this software.

## Contributing

Contributions are welcome. Please follow standard GitHub workflows.

## Contact

For questions about this project, open an issue on GitHub or contact the maintainers through the repository’s issue tracker.

