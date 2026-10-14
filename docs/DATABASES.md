# IPSpect — Database Architecture

IPSpect combines three complementary sources of information—**IANA**, **Rapid7 Recog**, and **ProjectDiscovery Nuclei**—to discover and identify network services. Each source has a distinct responsibility; none is treated as a complete or definitive inventory of what is running on a target.

## Responsibilities

| Source | Role in IPSpect | What it provides | What it does **not** establish |
| --- | --- | --- | --- |
| **IANA** | Service registration lookup | The service name registered for a TCP port | That the registered service is actually running there |
| **Rapid7 Recog** | Response fingerprinting | Patterns for interpreting observed banners, headers, and other supported response data | A response from the target; Recog does not send probes |
| **Nuclei** | Active service-detection requests | Compatible request templates and response-matching rules | That a service is present merely because a template is associated with a port |

IPSpect owns the scanning, request execution, evidence collection, comparison, and final result. These sources support those operations; they do not replace them.

## How they connect

```text
TCP port discovered open
          |
          v
   IANA port lookup
   (registered-service hint)
          |
          v
 Initial captured response
          |
          v
    Rapid7 Recog
    + built-in protocol checks
          |
          +---- Service identified? ---- Yes ---> Record fingerprint
          |                                     |
          No                                    |
          |                                     |
          v                                     |
 Built-in active protocol probes                |
          |                                     |
          +---- Service identified? ---- Yes ---+
          |
          No
          |
          v
  Gather existing evidence
  (port, IANA hint, banner,
   raw response, headers)
          |
          v
  Prioritize Nuclei requests
          |
          v
  IPSpect sends a request
          |
          v
     Target response
          |
          v
    Rapid7 Recog
          |
          +---- No match ---> Nuclei template matcher
          |                          |
          +--------------------------+
          |
          v
   Fingerprint or unknown
          |
          v
    Service resolver
          |
          v
   Final result + evidence
```

The path is **conditional**, not a requirement that every open port receives every type of probe. IPSpect can stop fingerprinting when an earlier stage provides a usable identification.

## IANA: a starting point, not proof

After finding an open TCP port, IPSpect looks up its registered service name in the IANA data. This provides useful context and may influence which probes are attempted first.

A port number alone cannot confirm a service: software can listen on nonstandard ports, and a registered port may be used by something entirely different. IPSpect keeps the IANA lookup separate from the detected service so a mismatch can be reported rather than hidden.

## Rapid7 Recog: interpret observed responses

Recog compares information captured from the target against fingerprint patterns. It may identify a service, product, or version and provide supporting evidence.

Recog does **not** establish a network connection or choose outgoing payloads. It operates on responses collected by IPSpect, whether those responses came from initial banner capture, built-in probes, or Nuclei-derived requests.

The available recognition coverage depends on the fingerprint data currently included with IPSpect and can expand independently of this architecture.

## Nuclei: obtain additional evidence

When earlier identification methods do not provide a usable result, IPSpect can use compatible Nuclei network detection templates as a source of **active probe payloads**.

IPSpect selects and prioritizes templates using its collected evidence—for example, a registered-service hint, the port, or already captured response content. These signals influence the **order** of requests; they are not proof of the service's identity, and a nonstandard port does not automatically exclude a template.

IPSpect sends the selected payload, captures the reply, and tries Recog first. If Recog does not recognize the response, the selected Nuclei template's response-matching rules provide an additional identification path.

Not every Nuclei template is suitable for this purpose. IPSpect loads only templates compatible with its supported detection-request format, rather than treating the full Nuclei collection as a general-purpose service probe database.

## Evidence and final service resolution

IPSpect keeps distinct concepts separate:

- **Registered service:** What IANA associates with the port.
- **Observed evidence:** The actual banner, headers, or response bytes returned by the target.
- **Fingerprint match:** An interpretation supported by Recog, built-in protocol validation, or a Nuclei template matcher.
- **Resolved service:** The final service identity IPSpect reports, together with its confidence and explanation.

Service-name aliases are normalized consistently when comparing registered names, detected names, and Nuclei template hints. Normalization helps compare terminology; it does not turn a port registration into a confirmed fingerprint.

If the evidence does not support an identification, IPSpect can report the service as **unknown** while preserving the available evidence and IANA suggestion.

## Design principles

- **Evidence over assumptions:** Actual responses take precedence over port-based guesses.
- **Independent responsibilities:** IANA suggests, Nuclei helps request, Recog interprets, and IPSpect resolves.
- **Nonstandard-port support:** Port registrations influence priority, not protocol eligibility.
- **Traceable results:** Preserve the basis for a fingerprint and distinguish confirmed from tentative identifications.
- **Extensible coverage:** New registrations, probes, and fingerprints may be added without redefining how the three sources cooperate.

This document describes the relationship between the databases and the IPSpect fingerprinting workflow. It intentionally does not enumerate the currently bundled protocols, template IDs, database files, or signature counts; those details may change over time.
