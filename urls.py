from django.urls import path

from . import views

app_name = "website"

urlpatterns = [
    path("", views.generator, name="generator"),
    path("r/<str:token>/", views.record_detail, name="record_detail"),
]
