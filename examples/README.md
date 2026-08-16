# Offline Audit Bundle examples

These directories are complete `full_audit_v1` Bundles. They need no API key,
network access, model call, or original run directory.

```bash
dcp verify examples/audits/sqlite-web
dcp verify examples/audits/virtual-catalyst
dcp verify examples/audits/sqlite-core
dcp verify examples/audits/device-calibration-core
```

The two complete three-gate examples replay to `Core=certified` and
`Evidence=certified`. The two secondary examples replay to `Core=certified`
with Evidence not tested. Every result is bounded by its frozen model, task,
budget, and challenger scope. None claims historical first discovery or formal
third-party issuance.

| Example | Plain-language task | Frozen model | Publication Bundle ID | Paper record ID |
| --- | --- | --- | --- | --- |
| `sqlite-web` | Choose up to four SQLite indexes that reduce measured query cost for a hidden workload | `deepseek-v4-flash` through Claude CLI | `sha256:eff6cf27afa58da58fc2591fff3be9116c0ee0fe896dc9f60a8c51376e504846` | `sha256:b3f0af47968ba2cb82afa0506deb14f32b58449ff6887039c8e015c1cfde6a3d` |
| `virtual-catalyst` | Tune a five-variable virtual catalyst recipe to maximize a sealed utility score | `deepseek-v4-pro` through Claude CLI | `sha256:fa17603f2184bb7b6a9a2432baa48766847fe27a4edcebd887697ccacfcaf1c2` | Same Bundle ID |
| `sqlite-core` | Choose SQLite indexes using local experimental feedback with Web disabled | `deepseek-v4-flash` through Claude CLI | `sha256:3690bebc8b3ac882ab17ad0f8a61b05ea630443dbc85e36965eabf27e1f1bbca` | Same Bundle ID |
| `device-calibration-core` | Calibrate a 24-control linear device from experimental measurements | `deepseek-v4-flash` through Claude CLI | `sha256:dff7b57b062362e036fb26e7da94959e7d4900e5007b839e43e5fa107a507945` | Same Bundle ID |

SQLite-Web has two content addresses for two envelopes. The paper record ID
identifies the canonical certificate record. The publication Bundle ID
identifies the self-contained `full_audit_v1` directory that packages the same
certificate with every kernel input needed by `dcp verify`. Their certificate
JSON objects are identical and have canonical object digest
`sha256:75b4e66adca9fc898f79804a5ed16c2a2366cb37fb459a02f2326680006b899e`.
The machine-readable mapping is [`audit-index.json`](audit-index.json).

The Bundle files are intentionally kept out of the PyPI wheel. They are
reference records for the GitHub repository, while the wheel contains only
the small verifier.
