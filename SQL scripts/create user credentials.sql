CREATE TABLE users (
    username CITEXT NOT NULL PRIMARY KEY,
    password CITEXT NOT NULL,
    enabled BOOLEAN NOT NULL
);

CREATE TABLE authorities (
    username CITEXT NOT NULL,
    authority CITEXT NOT NULL,
    CONSTRAINT fk_authorities_users FOREIGN KEY (username)
        REFERENCES users (username)
        ON DELETE CASCADE
);

CREATE UNIQUE INDEX ix_auth_username
    ON authorities (username, authority);
