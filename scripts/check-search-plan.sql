BEGIN;
SET LOCAL enable_seqscan = off;
EXPLAIN (ANALYZE, BUFFERS, FORMAT JSON)
SELECT area.revision_id
FROM private_data.professional_service_areas AS area
WHERE ST_DWithin(
    area.exact_center,
    ST_SetSRID(ST_MakePoint(72.8777, 19.0760), 4326)::geography,
    5000
)
ORDER BY ST_Distance(
    area.exact_center,
    ST_SetSRID(ST_MakePoint(72.8777, 19.0760), 4326)::geography
)
LIMIT 30;
ROLLBACK;
