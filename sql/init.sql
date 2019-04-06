CREATE DATABASE kubeserver;
USE kubeserver;
CREATE TABLE repositories (
  id VARCHAR(50) PRIMARY KEY,
  target VARCHAR(50),
  port VARCHAR(50),
  environment VARCHAR(200),
  repopath VARCHAR(200)
);