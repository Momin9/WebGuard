release: python3 manage.py migrate && python3 manage.py collectstatic --no-input
web: gunicorn vulnerability_scanner.wsgi --log-file -
