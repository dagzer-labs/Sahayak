-- Enable geospatial primitives before domain migrations introduce location data.
CREATE EXTENSION IF NOT EXISTS postgis;
