from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('scanning/', views.scanning, name="scanning"),
    path('check_task_status/<str:task_id>/', views.check_task_status, name='check_task_status'),
    path('output/', views.output_view, name='output'),
    path('port-scan/', views.port_scan, name='port_scan'),
    path('check_port_scan_status/<str:task_id>/', views.check_port_scan_status, name='check_port_scan_status'),

    path('about-us/', views.about_us, name='about_us'),
    path('contact-us/', views.contact_us, name='contact_us'),
    path('feedback/', views.feedback, name='feedback'),
]
