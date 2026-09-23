SELECT alias_name, alias_image
FROM demo_container_aliases
WHERE container_id = %(container_id)s;
