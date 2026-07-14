from django.contrib import admin
from .models import MLModel, MLPrediction


@admin.register(MLModel)
class MLModelAdmin(admin.ModelAdmin):
    list_display = ['name', 'model_type', 'version', 'accuracy', 'is_active', 'trained_at']
    list_filter = ['model_type', 'is_active']
    search_fields = ['name']


@admin.register(MLPrediction)
class MLPredictionAdmin(admin.ModelAdmin):
    list_display = ['id', 'model', 'prediction', 'confidence', 'created_at']
    list_filter = ['prediction']
    readonly_fields = ['id', 'input_data', 'features']
