-- Stage 4: mark bans the agent recorded while in dry-run mode.
-- A dry-run ban was never applied to the firewall, so restore and
-- auto-unban must never touch the firewall for it; the flag is how
-- stage 5 (gateway/UI) tells a simulated ban from a real one.
ALTER TABLE bans ADD COLUMN dry_run BOOLEAN NOT NULL DEFAULT false;
