SELECT id
FROM operations.search_load_points
WHERE ST_DWithin(
    center,
    ST_SetSRID(ST_MakePoint(72.8777, 19.0760), 4326)::geography,
    5000
)
ORDER BY ST_Distance(
    center,
    ST_SetSRID(ST_MakePoint(72.8777, 19.0760), 4326)::geography
)
LIMIT 30;
