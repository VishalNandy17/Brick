# Meta Model API in Brick

Brick uses Meta Model API for security workflows, not as an identity authority. The API key is server-side only. Set `MODEL_API_KEY` in the backend environment (see `backend/.env.example`); `META_AI_API_KEY` remains supported for existing deployments. The default model is `muse-spark-1.3`; set `META_AI_MODEL` to an enabled Muse Spark model to override it. Never put the key in frontend variables, browser bundles, audit records, or source control.

The backend currently implements:

- Security-event analysis over a minimized event view. Actor values are replaced with app-scoped pseudonyms; IP addresses, user agents, emails, wallets, free-form details, and metadata are not sent to Meta.
- Plain-language explanations for an audit event fetched by event ID and app ID. The endpoint ignores client-supplied event details and verifies that the selected event belongs to the developer's app.
- Authentication-policy posture review at `POST /api/v1/apps/:id/ai/recommend-auth-policy`. It sends only allowlisted enabled-method/configuration flags and grouped 30-day audit-event counts (event type/status/risk/count), never actor identities, emails, IPs, user agents, raw details, or metadata. The output is capped, schema-validated, explicitly advisory, and never mutates policy. A local deterministic fallback is available.
- Login anomaly detection at `POST /api/v1/apps/:id/ai/detect-login-anomalies`. It analyzes at most 1,000 recent app login events, correlates actor/IP HMAC pseudonyms, and adds deterministic repeated-failure and password-spraying signals. Raw network addresses and actor identifiers are never sent; results require human review and never block sign-in automatically.
- A deterministic local-rule fallback when the Meta key is missing or the API is unavailable. Responses label `provider` and `model`; local-rule results must not be presented as Meta-generated.

All four AI endpoints are limited to ten requests per minute per source IP per backend process. This in-memory limit is a local safeguard, not a distributed quota; production deployments with multiple replicas should also enforce a shared gateway/provider budget. Set a persistent `MODEL_PSEUDONYM_KEY` (32+ random bytes) distinct from the provider API key to keep app-scoped HMAC tokens stable across process restarts; absent this setting, Brick derives the key from `JWT_SECRET`, then falls back to a process-ephemeral random key.

Meta documents `https://api.meta.ai/v1` as the Model API base URL, Bearer-key authentication, and OpenAI-compatible Chat Completions; Meta recommends Muse Spark 1.3 for new work while retaining 1.1 as an available model. See [Meta Model API quickstart](https://dev.meta.ai/docs/quickstart), [Chat Completions](https://dev.meta.ai/docs/protocols/chat-completions), and [models](https://dev.meta.ai/docs/models).

## Remaining Brick-focused AI roadmap

1. **Incident investigation copilot:** summarize a bounded time window, connect events by pseudonymous actor, produce an evidence timeline, and suggest human-approved actions such as revoking a session or rotating a key. Model output never invokes these mutations.
2. **Policy authoring assistant:** translate a developer's request into a proposed, schema-validated policy draft, explain its impact against sample events, and require preview plus explicit owner approval before saving.
3. **Auth integration assistant:** generate provider-specific setup/checklists and SDK snippets from Brick's actual app configuration; validate values locally and never ask the model to see OAuth client secrets or signing keys.
4. **Recovery and support assistant:** explain OTP/MFA/passkey recovery steps and the evidence behind denials without disclosing credentials, recovery codes, or private identity attributes.

Before each use case ships, define data minimization, tenant authorization, model-output validation, rate/cost limits, auditability, and a safe deterministic fallback. AI findings are advisory and are not proof of compromise.
