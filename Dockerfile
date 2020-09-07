FROM python:3.7-alpine

# insalling git
RUN apk update
RUN apk add git

# workdir
ENV WORK_DIR /usr/src/app
WORKDIR ${WORK_DIR}

COPY requirements.txt ${WORK_DIR}
RUN chmod +x -R ${WORK_DIR}/requirements.txt

RUN pip install -r requirements.txt

COPY . .

CMD python waitress_server.py