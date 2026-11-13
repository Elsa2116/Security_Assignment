-- Create isolated namespaces before either migration runner or Better Auth starts.
CREATE SCHEMA IF NOT EXISTS app;
CREATE SCHEMA IF NOT EXISTS auth;
