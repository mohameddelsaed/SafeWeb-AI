from locust import HttpUser, task, between
import uuid

class SafeWebAIUser(HttpUser):
    wait_time = between(1, 5)

    def on_start(self):
        """Called when a Locust start before any task is scheduled."""
        # Create a unique user for this session
        self.username = f"locust_{uuid.uuid4().hex[:8]}@example.com"
        self.password = "Password123!"
        
        # We assume the user exists or we create one via API if open registration exists.
        # Since this is a load test against the local env, we might want to ensure users exist
        # beforehand or use a shared user. Let's use a shared user for simplicity, but in
        # reality, we'd provision users.
        self.username = "testuser@example.com"
        
        # Login
        response = self.client.post("/api/v1/auth/login/", json={
            "email": self.username,
            "password": self.password
        })
        
        if response.status_code == 200:
            self.token = response.json().get("tokens", {}).get("access")
            self.headers = {"Authorization": f"Bearer {self.token}"}
        else:
            self.headers = {}
            # print(f"Login failed: {response.status_code}")

    @task(3)
    def dashboard_polling(self):
        """Simulate polling the dashboard/stats"""
        self.client.get("/api/v1/dashboard/stats/", headers=self.headers, name="/api/v1/dashboard/stats/")

    @task(1)
    def scan_lifecycle(self):
        """Simulate creating a scan and polling it"""
        # Create scan
        response = self.client.post("/api/v1/scan/website/", json={
            "target": "https://example.com",
            "scan_depth": "fast",
            "scope_type": "single_domain"
        }, headers=self.headers, name="Create Scan")
        
        if response.status_code == 201:
            scan_id = response.json().get("id")
            
            # Poll a few times
            for _ in range(5):
                self.client.get(f"/api/v1/scan/{scan_id}/", headers=self.headers, name="Poll Scan")
                import time
                time.sleep(1)
