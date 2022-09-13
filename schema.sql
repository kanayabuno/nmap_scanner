DROP TABLE IF EXISTS ports;

CREATE TABLE ports (
  hostname varchar(100) PRIMARY KEY,
  openports varchar(max) NOT NULL
);