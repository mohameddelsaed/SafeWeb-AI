from django.urls import path
from . import views

urlpatterns = [
    path('articles/', views.ArticleListView.as_view(), name='article-list'),
    path('articles/<slug:slug>/', views.ArticleDetailView.as_view(), name='article-detail'),
    path('categories/', views.ArticleCategoryListView.as_view(), name='article-categories'),
    path('tags/', views.ArticleTagListView.as_view(), name='article-tags'),
]
