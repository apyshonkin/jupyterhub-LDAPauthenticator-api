FROM python:3.9-slim

WORKDIR /app

COPY app.py /app

RUN --mount=type=bind,source=requirements.txt,target=/tmp/requirements.txt pip install --no-cache-dir -r /tmp/requirements.txt

CMD ["python", "app.py"]
