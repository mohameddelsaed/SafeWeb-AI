# 08 - Scanner Engine Test Suite

## Objective
Validate the core scanning pipeline without triggering real-world network attacks.

## Scope
- Celery Task Orchestration (`execute_scan_task`)
- Subprocess Wrappers (`NucleiWrapper`, `NmapWrapper`)
- Vulnerability Deduplication

## Specifications
1. **Mock Execution**:
   - Mock `subprocess.run` to return a predefined JSON string representing Nuclei output.
   - Dispatch `execute_scan_task`.
   - Assert `Vulnerability` objects are created from the mocked stdout.
2. **Deduplication**:
   - Send two identical vulnerabilities to the database.
   - Assert the second one increments the `count` or is ignored rather than creating a duplicate row.

## AI Prompt Instructions
"Use `unittest.mock.patch` extensively to intercept `subprocess.run` inside `backend/apps/scanning/engine/tools/`. Ensure the Orchestrator successfully traverses phases (recon -> crawl -> scan -> finalize)."\n