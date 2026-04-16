"""GraphQL introspection probe.

If the directory fuzzer or CMS scanner discovered /graphql or /graphiql,
we attempt a full introspection query. A production GraphQL endpoint that
answers introspection hands every query, mutation, type and field to an
attacker — the equivalent of publishing your entire API schema.
"""
from __future__ import annotations

from typing import Callable

import httpx

from app.scanners._baseline import fetch_baselines, is_catchall
from app.scanners.base import Finding, ScanResult, Severity

USER_AGENT = "MVZ-SelfScan/1.0 (+https://scan.zdkg.de)"

INTROSPECTION_QUERY = """{"query":"{ __schema { queryType { name } mutationType { name } types { name kind fields { name type { name kind } } } } }"}"""

GRAPHQL_PATHS = ("/graphql", "/graphiql", "/api/graphql", "/gql", "/query")


def check_graphql(domain: str, result: ScanResult, step: Callable[[str, int], None]) -> None:
    step("GraphQL Introspection", 58)

    baselines = fetch_baselines(domain)

    with httpx.Client(
        timeout=8.0,
        follow_redirects=False,
        headers={"User-Agent": USER_AGENT, "Content-Type": "application/json"},
    ) as client:
        for path in GRAPHQL_PATHS:
            try:
                r = client.post(f"https://{domain}{path}", content=INTROSPECTION_QUERY)
            except httpx.HTTPError:
                continue

            if r.status_code != 200:
                continue
            ct = r.headers.get("content-type", "").lower()
            if "json" not in ct:
                continue

            body = r.text[:16384]
            if is_catchall(body, baselines):
                continue

            try:
                data = r.json()
            except ValueError:
                continue

            # Check for the __schema key — definitive proof of introspection
            schema = (data.get("data") or {}).get("__schema")
            if not schema:
                continue

            types = schema.get("types") or []
            type_names = [t.get("name") for t in types if isinstance(t, dict)]
            query_type = (schema.get("queryType") or {}).get("name")
            mutation_type = (schema.get("mutationType") or {}).get("name")

            # Filter out internal types (__Type, __Field, etc.)
            user_types = [n for n in type_names if n and not n.startswith("__")]
            mutations_available = mutation_type is not None

            result.metadata["graphql_introspection"] = {
                "path": path,
                "types_count": len(user_types),
                "user_types": user_types[:50],
                "query_type": query_type,
                "mutation_type": mutation_type,
            }

            sev = Severity.HIGH if mutations_available else Severity.MEDIUM

            result.add(Finding(
                id="deep.graphql_introspection_open",
                title=f"GraphQL-Introspection offen auf {path} ({len(user_types)} Typen, {'Mutations' if mutations_available else 'Query-only'})",
                description=(
                    f"Der GraphQL-Endpunkt unter {path} beantwortet Introspection-Queries "
                    f"ohne Authentifizierung. Das Schema enthält {len(user_types)} Typen "
                    f"(Queries über '{query_type}'"
                    + (f", Mutations über '{mutation_type}'" if mutation_type else "")
                    + "). Ein Angreifer kennt damit die vollständige API-Struktur und kann "
                    "gezielt nach unsicheren Queries/Mutations suchen."
                    + ("\n\nMutations verfügbar — ein Angreifer kann möglicherweise Daten ändern." if mutations_available else "")
                ),
                severity=sev,
                category="Deep Scan",
                evidence={
                    "path": path,
                    "types": user_types[:30],
                    "mutations": mutations_available,
                },
                recommendation=(
                    "Introspection in der Produktion deaktivieren. Bei Apollo Server: "
                    "`introspection: false`, bei Hasura: `HASURA_GRAPHQL_ENABLE_ALLOWLIST=true`."
                ),
            ))
            return  # Found one, stop probing further paths
