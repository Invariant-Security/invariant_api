SELECT alias_label, alias_address
FROM demo_host_aliases
WHERE endpoint_id = %(endpoint_id)s;
