UPDATE leads
SET slack_notified_at = CASE WHEN %(notified)s THEN now() ELSE slack_notified_at END,
    slack_notify_attempts = %(attempts)s,
    slack_last_error = %(last_error)s
WHERE id = %(id)s;
