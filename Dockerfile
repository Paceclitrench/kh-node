FROM python:3.11-slim
WORKDIR /app
RUN pip install --no-cache-dir requests
COPY dashscope_hunt.py sidecar.py start.sh fetch_tokens.py key_patterns.py ./
RUN touch gh_tokens.txt && chmod +x start.sh
ENV KF_THREADS=4 KF_PAGES=5 KF_DORK_MOD=30
CMD ["bash", "start.sh"]
