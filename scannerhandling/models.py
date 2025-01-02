from django.db import models


class Vulnerability(models.Model):
    name = models.CharField(max_length=255)  # Type of vulnerability (e.g., XSS, SQL Injection)
    description = models.TextField()  # Details about the vulnerability
    severity = models.IntegerField()  # 1-Low, 2-Medium, 3-High
    business_context = models.TextField(blank=True, null=True)  # Optional context
    data_sensitivity = models.TextField(blank=True, null=True)  # Optional sensitivity details
    payload = models.TextField(blank=True, null=True)  # Payload used to detect the vulnerability
    detected_at = models.DateTimeField(auto_now_add=True)
    scan_result = models.ForeignKey(
        'ScanResult',
        on_delete=models.CASCADE,
        related_name="detected_vulnerabilities"  # Updated related_name to avoid clash
    )


class Feedback(models.Model):
    vulnerability = models.ForeignKey('Vulnerability', on_delete=models.CASCADE)  # Ensure 'on_delete' is set
    feedback_text = models.TextField()
    submitted_at = models.DateTimeField(auto_now_add=True)


class ScanResult(models.Model):
    url = models.URLField()
    headers = models.JSONField()
    vulnerabilities = models.JSONField()
    scan_date = models.DateTimeField(auto_now_add=True)


class ContactMessage(models.Model):
    name = models.CharField(max_length=100)
    email = models.EmailField()
    subject = models.CharField(max_length=200)
    message = models.TextField()
    timestamp = models.DateTimeField(auto_now_add=True)

    def __str__(self):
        return f"{self.name} - {self.subject}"
