CREATE DATABASE keycloakdb;
CREATE USER keycloakusr WITH PASSWORD 'keycloakpwd';
GRANT ALL PRIVILEGES ON DATABASE keycloakdb TO keycloakusr;

\c keycloakdb;
GRANT ALL ON SCHEMA public TO keycloakusr;
