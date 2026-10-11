DROP TABLE IF EXISTS signup_sessions;
DROP TRIGGER IF EXISTS users_number_immutable ON users;
DROP FUNCTION IF EXISTS forbid_number_change();
DROP TABLE IF EXISTS users;
DROP TABLE IF EXISTS number_registry;
