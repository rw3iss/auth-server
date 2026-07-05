-- 019: per-app outbound webhooks.
--
-- apps.webhooks is a JSONB array of webhook configs:
--   [{ "name": "Slack signups", "url": "https://hooks.slack.com/...",
--      "events": ["user.registered"], "enabled": true }]
--
-- Dispatch is async + best-effort from the auth-server when an event in
-- the config's `events` list fires for the app (currently only
-- "user.registered" — new-user creation through that app). URLs under
-- hooks.slack.com get a Slack-formatted {"text": ...} payload; everything
-- else receives the full JSON event envelope.
ALTER TABLE apps ADD COLUMN IF NOT EXISTS webhooks JSONB NOT NULL DEFAULT '[]'::jsonb;

COMMENT ON COLUMN apps.webhooks IS
    'Array of outbound webhook configs: [{name, url, events[], enabled}]. Dispatched async on matching events (user.registered).';
