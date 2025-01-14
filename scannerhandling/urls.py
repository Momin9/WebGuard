from django.urls import path

from . import views

urlpatterns = [
    path('', views.home, name="home"),
    path('scanning/', views.scanning, name="scanning"),
    path('check_task_status/<str:task_id>/', views.check_task_status, name='check_task_status'),
    path('output/', views.output_view, name='output'),
    path('port-scan/', views.port_scan, name='port_scan'),
    path('check_port_scan_status/<str:task_id>/', views.check_port_scan_status, name='check_port_scan_status'),
    path('contact-us/', views.contact_us, name='contact_us'),
    path('feedback/', views.feedback, name='feedback'),
    path('generate-report/', views.generate_report_page, name='generate_report'),
    path('download-pdf/', views.download_pdf, name='download_pdf'),
    path('download-csv/', views.download_csv, name='download_csv'),
]
