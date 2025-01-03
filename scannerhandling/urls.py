from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('about-us/', views.about_us, name='about_us'),
    path('contact-us/', views.contact_us, name='contact_us'),
    path('feedback/', views.feedback, name='feedback'),
    path('custom-report/', views.generate_custom_report, name='generate_custom_report'),
    path('port-scan/', views.port_scan, name='port_scan'),
]
