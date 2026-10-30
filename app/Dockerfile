FROM python:3.13-slim
COPY requirements.txt /tmp/requirements.txt
RUN pip install --no-cache-dir -r /tmp/requirements.txt
COPY mikrokat.py store.py web.py actions.py sso.py geo.py health.py worldmap.json /app/
ENTRYPOINT ["python3", "-u", "/app/mikrokat.py"]
