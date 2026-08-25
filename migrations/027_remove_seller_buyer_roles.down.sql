-- Down: deliberately does NOT recreate `seller` and `buyer`.
--
-- They were demo-seed artefacts on a civic platform, not a feature anyone depends on, and nothing held
-- them. Recreating them would reintroduce the exact bug this migration fixes — every new organisation
-- offering marketplace roles again. A down migration that restores a defect is worse than one that
-- declines to.
SELECT 1;
