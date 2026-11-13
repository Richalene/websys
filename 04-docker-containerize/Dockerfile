# SecureNotes API — Dockerfile
# Pinned, slim base image (TASK A1)
FROM python:3.12-slim

# Set working directory (TASK A2)
WORKDIR /app

# Optimize layer caching: copy requirements and install dependencies before source code (TASK A3)
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy source code (TASK A4)
COPY . .

# Run as non-root user for container security (TASK B1)
RUN adduser --disabled-password --gecos "" appuser
USER appuser

# Expose port and start API bound to 0.0.0.0 (TASK A5)
EXPOSE 8000
CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
