-- rfc8693 is the default token profile. The service, not this column default,
-- decides the profile of a tenant with no row (domain.DefaultTokenProfile);
-- this keeps a row inserted without a profile consistent with it.
ALTER TABLE tenant_settings ALTER COLUMN token_profile SET DEFAULT 'rfc8693';
