#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"
CLIENTS=${CLIENTS:-10}
DURATION=${DURATION:-10}

psql "$DATABASE_URL" --set ON_ERROR_STOP=1 <<'SQL'
DROP TABLE IF EXISTS operations.search_load_points;
CREATE UNLOGGED TABLE operations.search_load_points (
    id bigint PRIMARY KEY,
    center geography(Point, 4326) NOT NULL
);
INSERT INTO operations.search_load_points (id, center)
SELECT value,
       ST_SetSRID(ST_MakePoint(
           72.8777 + sin(value::double precision) * 0.35,
           19.0760 + cos(value::double precision) * 0.35
       ), 4326)::geography
FROM generate_series(1, 50000) AS value;
CREATE INDEX search_load_points_gist_idx ON operations.search_load_points USING gist(center);
ANALYZE operations.search_load_points;
SQL

pgbench "$DATABASE_URL" --no-vacuum --client="$CLIENTS" --jobs="$CLIENTS" \
  --time="$DURATION" --file=scripts/search-load-query.sql

psql "$DATABASE_URL" --set ON_ERROR_STOP=1 --command \
  "DROP TABLE operations.search_load_points;"
