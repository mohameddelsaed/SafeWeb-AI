# 05 - Performance Test Suite Specification

## Objective
Validate the system handles high-volume target ingestion and concurrent scanning using Locust.

## Scope
- API throughput for Dashboard polling.
- Celery Queue backpressure handling.

## Specifications
1. **Locust Scenario 1: Scan Polling**
   - 500 concurrent users polling `/api/v1/scan/{id}/` every 5 seconds.
   - Assert 99th percentile response time < 200ms.
2. **Celery Load Test**:
   - Dispatch 100 scans simultaneously.
   - Assert memory usage of `celery_worker` container stays below 2GB.
   - Assert no dropped tasks.

## AI Prompt Instructions
"Write a `locustfile.py` defining an authenticated user flow. Setup `HttpUser` to login, retrieve token, start a scan, and poll for results until completion."\n