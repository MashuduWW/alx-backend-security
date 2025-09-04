Django Security Middleware & IP Management

This project provides a robust framework for managing IP-based security in a Django application. It includes logging, geolocation, rate limiting, blacklisting, suspicious activity detection, and compliance features. The goal is to enhance security while maintaining a fair user experience.

## Features
1. Middleware for Logging

Captures IP addresses and request metadata.

Logs stored for auditing and analysis.

2. Geolocation Integration

Uses third-party Geolocation APIs (e.g., MaxMind, IPStack, GeoIP).

Manages API usage efficiently with caching and rate-limiting strategies.

3. Rate Limiting

Supports both:

Django-native solutions (via middleware or DRF throttling).

Redis-based solutions for high-performance environments.

4. Blacklist & IP Management

Django models or Redis cache used to block harmful IPs.

Admin dashboard for adding/removing IPs.

Real-time blocking support.

5. Suspicious Behavior Detection

Scheduled tasks (via Celery/CRON) to analyze logs.

Detects anomalies (e.g., brute-force login attempts, scraping).

Generates alerts and applies automated restrictions.

6. Compliance (GDPR/CCPA)

Anonymization of stored IP data where required.

Configurable data retention policies.

Provides balance between security enforcement and user privacy.

7. Balancing Security & UX

Avoids excessive blocking that frustrates legitimate users.

Implements progressive sanctions: warnings → temporary ban → permanent ban.

## Tech Stack

Django (middleware, models, admin integration)

Redis (caching, rate limiting, blacklisting)

Celery (background tasks for log analysis)

Geolocation APIs (third-party providers)

PostgreSQL / MySQL (log & blacklist storage)