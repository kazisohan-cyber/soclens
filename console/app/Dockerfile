FROM python:3.12-slim

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
WORKDIR /srv
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY soclens ./soclens
RUN useradd --system --uid 10001 soclens && mkdir -p /data && chown soclens /data
USER soclens
EXPOSE 8000
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:8000/healthz').status==200 else 1)"
# One worker: the background job loop (expiry, write-back, retention) runs inside the app process.
CMD ["uvicorn", "soclens.main:app", "--host", "0.0.0.0", "--port", "8000", "--workers", "1", "--no-server-header"]
