import requests
from celery.result import AsyncResult
from django.conf import settings
from django.core.mail import send_mail
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

from scannerhandling.models import ContactMessage
from scannerhandling.models import Vulnerability, Feedback
from .tasks import run_scanner_task, run_port_scan_task


# Django View for Displaying Results
def home(request):
    return render(request, 'home.html')


import logging

logger = logging.getLogger(__name__)


def scanning(request):
    logger.info(f"Request received: {request.method}, Data: {request.POST}")
    url = request.POST.get('url', '').strip()

    if not url:
        return render(request, 'home.html', {"error": "No URL provided for scanning."})

    # Start the Celery task
    task = run_scanner_task.delay(url)

    # Inform the user that the task is running
    return render(request, 'home.html', {
        "info": "Scanning task has been started. Please wait...",
        "task_id": task.id  # Pass the task ID to the template
    })


def check_task_status(request, task_id):
    task = AsyncResult(task_id)  # Get the task result using its ID

    if task.state == 'PENDING':
        return JsonResponse({"status": "PENDING", "info": "Task is still running..."})
    elif task.state == 'SUCCESS':
        # Task completed successfully, return the result
        return JsonResponse({"status": "SUCCESS", "result": task.result})
    elif task.state == 'FAILURE':
        # Task failed, return the error message
        return JsonResponse({"status": "FAILURE", "error": str(task.result)})
    else:
        # Any other state (e.g., RETRY)
        return JsonResponse({"status": task.state})


def output_view(request):
    # Fetch results from the database or task result
    task_id = request.GET.get('task_id')
    task = AsyncResult(task_id)

    if task.state == 'SUCCESS':
        context = task.result
        return render(request, 'output.html', context)
    else:
        return render(request, 'output.html', {"error": "Task is not complete yet."})


def about_us(request):
    return render(request, 'about_us.html')


def feedback(request):
    if request.method == 'POST':
        vulnerability_id = request.POST.get('vulnerability_id')
        feedback_text = request.POST.get('feedback')
        if vulnerability_id is None or feedback_text is None:
            return render(request, 'feedback.html', {'feedback_text': "The vulnerability exists"})
        # Ensure the vulnerability exists
        vulnerability = get_object_or_404(Vulnerability, id=vulnerability_id)

        # Create the feedback record
        Feedback.objects.create(vulnerability=vulnerability, feedback_text=feedback_text)
        return render(request, 'feedback.html', {'message': 'Feedback submitted successfully'})

    vulnerabilities = Vulnerability.objects.all()
    return render(request, 'feedback.html', {'vulnerabilities': vulnerabilities})


import os

OPENAI_API_KEY = os.getenv("OPENAI_API_KEY")


def generate_custom_report(request):
    report = None
    if request.method == 'POST':
        details = request.POST.get('details', '')

        # Your API logic here
        url = "https://api.openai.com/v1/chat/completions"
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": "You are an assistant for generating professional reports."},
                {"role": "user", "content": f"Generate a professional report based on: {details}"}
            ]
        }
        headers = {
            "Authorization": f"Bearer {OPENAI_API_KEY}",
            "Content-Type": "application/json"
        }
        response = requests.post(url, json=payload, headers=headers)
        if response.status_code == 200:
            data = response.json()
            report = data["choices"][0]["message"]["content"]
        else:
            report = "An error occurred. Please try again."

    return render(request, 'generate_custom_report.html', {'report': report})


def contact_us(request):
    if request.method == 'POST':
        name = request.POST.get('name')
        email = request.POST.get('email')
        subject = request.POST.get('subject', 'No Subject')
        message = request.POST.get('message')

        # Save the message in the database
        ContactMessage.objects.create(
            name=name,
            email=email,
            subject=subject,
            message=message
        )

        # Send email to admin
        admin_email = settings.EMAIL_HOST_USER
        email_subject = f"New Contact Message: {subject}"
        email_message = (
            f"You have received a new message from your contact form:\n\n"
            f"Name: {name}\n"
            f"Email: {email}\n"
            f"Subject: {subject}\n\n"
            f"Message:\n{message}\n"
        )

        try:
            send_mail(
                email_subject,
                email_message,
                settings.EMAIL_HOST_USER,
                [admin_email],
                fail_silently=False,
            )
            success_message = 'Your message has been sent successfully. We will get back to you soon!'
        except Exception:
            success_message = 'There was an error sending your message. Please try again later.'

        return render(request, 'contact_us.html', {'success_message': success_message})

    return render(request, 'contact_us.html')


@csrf_exempt
def port_scan(request):
    if request.method == 'POST':
        host = request.POST.get('host', '').strip()

        if not host:
            return render(request, 'port_scan_results.html', {'error': 'Please provide a valid host'})

        # Start the background task
        task = run_port_scan_task.delay(host)

        # Inform the user the task is running and provide the task ID
        return render(request, 'port_scan_results.html', {
            'info': "Port scanning task has been started. Please wait...",
            'task_id': task.id,  # Pass the task ID for polling
        })

    return render(request, 'port_scan_results.html', {'error': 'No scan initiated'})


def check_port_scan_status(request, task_id):
    task = AsyncResult(task_id)

    if task.state == 'PENDING':
        return JsonResponse({"status": "PENDING", "info": "Task is still running..."})
    elif task.state == 'SUCCESS':
        return JsonResponse({"status": "SUCCESS", "result": task.result})
    elif task.state == 'FAILURE':
        return JsonResponse({"status": "FAILURE", "error": str(task.result)})
    else:
        return JsonResponse({"status": task.state})
