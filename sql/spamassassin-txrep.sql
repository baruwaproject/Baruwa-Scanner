DELETE FROM txrep WHERE last_hit <= (NOW() - INTERVAL '120 days');
