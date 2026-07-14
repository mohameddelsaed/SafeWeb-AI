import uuid
from django.db import models


class MLModel(models.Model):
    """Stores metadata about trained ML models."""
    MODEL_TYPES = [
        ('malware', 'Malware Detection'),
        ('phishing', 'Phishing Detection'),
        ('anomaly', 'Anomaly Detection'),
    ]

    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    name = models.CharField(max_length=200)
    model_type = models.CharField(max_length=20, choices=MODEL_TYPES)
    version = models.CharField(max_length=20, default='1.0.0')
    accuracy = models.FloatField(null=True, blank=True)
    precision_score = models.FloatField(null=True, blank=True)
    recall = models.FloatField(null=True, blank=True)
    f1_score = models.FloatField(null=True, blank=True)
    file_path = models.CharField(max_length=500, blank=True)
    is_active = models.BooleanField(default=False)
    training_samples = models.IntegerField(default=0)
    training_duration_seconds = models.FloatField(null=True, blank=True)
    trained_at = models.DateTimeField(null=True, blank=True)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.name} v{self.version} ({self.model_type})'


class MLPrediction(models.Model):
    """Stores individual ML predictions for audit/analysis."""
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    model = models.ForeignKey(MLModel, on_delete=models.SET_NULL, null=True, related_name='predictions')
    scan = models.ForeignKey('scanning.Scan', on_delete=models.CASCADE, null=True, blank=True, related_name='ml_predictions')
    input_data = models.JSONField(default=dict)
    prediction = models.CharField(max_length=50)  # 'malicious', 'benign', 'phishing', 'legitimate'
    confidence = models.FloatField()
    features = models.JSONField(default=dict)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.prediction} ({self.confidence:.1%})'


from pgvector.django import VectorField

class ExploitMemory(models.Model):
    id = models.UUIDField(primary_key=True, default=uuid.uuid4, editable=False)
    technology_stack = models.CharField(max_length=255)
    vulnerability_class = models.CharField(max_length=100)
    attack_strategy_summary = models.TextField()
    successful_payload = models.TextField()
    vector_embedding = VectorField(dimensions=1536)
    created_at = models.DateTimeField(auto_now_add=True)

    class Meta:
        db_table = 'exploit_memories'
        ordering = ['-created_at']

    def __str__(self):
        return f'{self.vulnerability_class} on {self.technology_stack}'

