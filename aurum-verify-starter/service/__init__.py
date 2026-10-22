"""aurum-verify — evidence-backed verification API for autonomous agents.

The product is one narrow, billable outcome:

    "Every claim in this payload is independently checked against live sources,
     and every quote used as evidence is verified verbatim — or the claim is
     reported unverified. You get a machine-readable receipt."

Why an agent pays instead of checking itself: a generator and a verifier that
share the same weights share the same blind spots, and a self-check cannot
produce a second, independent evidence trail. This service is the independent
second opinion, and it refuses to assert anything its own code could not
corroborate.
"""

__version__ = "0.1.0"
