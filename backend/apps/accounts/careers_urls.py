from django.urls import path
from . import views

urlpatterns = [
    path('apply/', views.JobApplicationView.as_view(), name='job-apply'),
]
