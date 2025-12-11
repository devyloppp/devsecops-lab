FROM python:3.9-alpine

WORKDIR /app

# Copy requirements first for better layer caching
COPY api/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY api .

# Run as non-root user
RUN addgroup -g 1000 appuser && adduser -D -u 1000 -G appuser appuser
USER appuser

EXPOSE 5000

CMD ["python", "app.py"]