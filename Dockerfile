FROM abe-lambda_backup:pv4
ENTRYPOINT []
RUN cd /var/task && rm -rf keys tests "docker commands.docx" "~\$cker commands.docx" __pycache__
RUN python -m pip install --no-cache-dir flask httpx gunicorn
ENV PYTHONUNBUFFERED=1
WORKDIR /app
COPY *.py /app/
