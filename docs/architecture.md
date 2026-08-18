# Architecture (High-level)

```mermaid
flowchart TD
  A[User Browser] -->|POST /scan| B[Flask Frontend]
  B --> C[Scan Controller (Blueprint)]
  C --> D[Analysis Modules]
  D --> D1[headers]
  D --> D2[ssl_check]
  D --> D3[dns]
  D --> D4[https_check]
  D --> D5[cookies]
  D --> D6[robots]
  D --> D7[sitemap]
  D --> D8[admin_pages]
  C --> E[Services]
  E --> F[score_engine]
  E --> G[risk_engine]
  E --> H[recommendation_engine]
  C --> I[report generator]
  I --> J[WeasyPrint/xhtml2pdf]
  style B fill:#f9f,stroke:#333,stroke-width:1px
```

ملاحظات:
- Execution model: synchronous request -> analyses -> aggregation -> report generation.
- Can be upgraded to asynchronous worker model (Celery + Redis) for long-running scans.
