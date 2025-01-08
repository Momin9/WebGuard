import csv
import tempfile

from bs4 import BeautifulSoup
from celery.result import AsyncResult
from django.conf import settings
from django.core.mail import send_mail
from django.http import HttpResponse
from django.http import JsonResponse
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.template import loader
from django.views.decorators.csrf import csrf_exempt
from weasyprint import HTML

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


def generate_report_page(request):
    template = loader.get_template('generate_report.html')
    return HttpResponse(template.render({}, request))


def download_pdf(request):
    title = request.GET.get('title', 'Report')
    content = request.GET.get('content', '<p>No content provided.</p>')

    # Construct HTML for the PDF
    html_template = f"""
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <style>
            body {{
                font-family: 'Arial', sans-serif;
                line-height: 1.6;
                margin: 20px;
            }}
            h1 {{
                text-align: center;
                color: #00334e;
            }}
            .content {{
                margin-top: 20px;
            }}
        </style>
    </head>
    <body>
        <h1>{title}</h1>
        <div class="content">{content}</div>
    </body>
    </html>
    """

    # Generate PDF using WeasyPrint
    pdf_content = HTML(string=html_template).write_pdf()

    # Send the PDF as a response
    response = HttpResponse(pdf_content, content_type='application/pdf')
    response['Content-Disposition'] = f'attachment; filename="{title}.pdf"'

    return response


def download_csv(request):
    title = request.GET.get('title', 'Report')
    content = request.GET.get('content', '<p>No content provided.</p>')

    # Extract plain text from HTML
    soup = BeautifulSoup(content, "html.parser")
    plain_text = soup.get_text()

    # Create CSV response
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{title}.csv"'
    writer = csv.writer(response)

    # Write the title and content
    writer.writerow(['Title', 'Content'])
    writer.writerow([title, plain_text])

    return response
