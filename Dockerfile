FROM python:3.7-alpine

# workdir
ENV WORK_DIR /usr/src/app
WORKDIR ${WORK_DIR}

COPY requirements.txt ${WORK_DIR}
RUN chmod +x -R ${WORK_DIR}/requirements.txt

RUN pip install -r requirements.txt

CMD python waitress_server.py