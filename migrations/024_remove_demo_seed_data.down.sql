-- Revert 024: intentionally a no-op. Rolling back the removal must NOT re-seed
-- the demo organizations/users — they are gone by design. Re-create manually if
-- ever needed.
SELECT 1;
