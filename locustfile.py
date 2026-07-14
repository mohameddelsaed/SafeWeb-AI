import time
from locust import HttpUser, task, between, events

class SafeWebAIUser(HttpUser):
    wait_time = between(1, 5)

    def on_start(self):
        """On start, log in and get the access token."""
        self.access_token = None
        self.scan_id = None
        
        # We need a user to log in. In a real load test, we'd have a pool of users.
        # We will assume a test user exists or register one dynamically.
        # Let's assume testuser@example.com / password123!
        response = self.client.post("/auth/login/", json={
            "email": "testuser@example.com",
            "password": "password123!"
        })
        
        if response.status_code == 200:
            self.access_token = response.json().get("tokens", {}).get("access")
            
    @task(1)
    def create_and_poll_scan(self):
        if not self.access_token:
            return
            
        headers = {
            "Authorization": f"Bearer {self.access_token}"
        }
        
        # 1. Create a scan
        payload = {
            "target": "https://example.com",
            "scanType": "website",
            "scanDepth": "shallow"
        }
        
        with self.client.post("/scan/website/", json=payload, headers=headers, catch_response=True) as response:
            if response.status_code in [200, 201]:
                self.scan_id = response.json().get("id")
                response.success()
            else:
                response.failure(f"Failed to create scan: {response.status_code}")
                return
                
        # 2. Poll for scan results
        # We simulate the polling scenario 
        # The spec: "500 concurrent users polling /api/v1/scan/{id}/ every 5 seconds."
        # Wait for 5 seconds between polls
        for _ in range(6): # Poll up to 6 times (~30 seconds)
            time.sleep(5)
            with self.client.get(f"/scan/{self.scan_id}/", headers=headers, name="/scan/[id]/", catch_response=True) as poll_resp:
                if poll_resp.status_code == 200:
                    status = poll_resp.json().get("status")
                    if status == "completed" or status == "failed":
                        poll_resp.success()
                        break
                    else:
                        poll_resp.success()
                else:
                    poll_resp.failure(f"Failed to poll scan: {poll_resp.status_code}")
                    break
