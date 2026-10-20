FROM python:3.11-slim
WORKDIR /app
COPY dashscope_hunt.py sidecar.py start.sh ./
COPY gh_tokens.txt ./
RUN chmod +x start.sh
ENV KF_THREADS=4 KF_PAGES=5 KF_DORK_MOD=30 KF_DORK_SHARD=0
CMD ["bash", "start.sh"]
