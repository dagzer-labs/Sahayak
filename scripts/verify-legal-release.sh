#!/bin/sh
set -eu

: "${DATABASE_URL:?DATABASE_URL is required}"

expected_version=$(sed -n 's/.*"recorded_consent_version": "\([^"]*\)".*/\1/p' resources/legal/manifest.json)
test -n "$expected_version"

for entry in \
  "privacy-v1.html 636462492e2a0d139ea9708c9a0cd37f7527a678651e0ef86ad3dbb9e37dedd2" \
  "terms-v1.html 9d741928e5674bd5dbae6c207859a67fa43a856cf4083e008d682b221db44e80" \
  "contact-v1.html 304f8b7abc480d94c14d37989bc48bea39f28e8c0c819c225c0baa3fb2738865" \
  "deletion-v1.html 8d165e8f6dcb0fa12ca24cacc151a50000c0488ffc3b07b3e738296d5880472e"
do
  set -- $entry
  actual=$(sha256sum "resources/legal/$1" | cut -d ' ' -f 1)
  test "$actual" = "$2"
done

database_versions=$(psql "$DATABASE_URL" --tuples-only --no-align --set ON_ERROR_STOP=1 --command \
  "SELECT string_agg(DISTINCT document_version, ',' ORDER BY document_version) FROM profile.consent_documents WHERE is_current")
test "$database_versions" = "$expected_version"
