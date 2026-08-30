UPDATE contracts SET status = 'paid', paid_at = now()
WHERE id = %(id)s AND status = 'pending';
