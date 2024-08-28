FROM python:3.9-slim

WORKDIR /app

COPY . /app

RUN pip install --no-cache-dir flask ldap3 pyjwt flask-limiter

CMD ["python", "app.py"]
