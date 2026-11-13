-- Data-only migration: '' and NULL both mean "no parent" (and "no delegating
-- agent"), so there is nothing to undo.
SELECT 1;
