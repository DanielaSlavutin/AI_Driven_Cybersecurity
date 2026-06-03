FROM python:3.10-slim

WORKDIR /app

RUN apt-get update && apt-get install -y \
    libpcap-dev \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir torch --index-url https://download.pytorch.org/whl/cpu
RUN pip install --no-cache-dir -r requirements.txt

COPY . .

EXPOSE 8501

CMD ["streamlit", "run", "ui_app.py", "--server.port=8501", "--server.address=0.0.0.0", "--server.maxUploadSize=1000"]