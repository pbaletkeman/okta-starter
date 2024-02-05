FROM python:3.11-slim

ENV JAVA_HOME=/opt/java/openjdk
# alpine jre is less then 1 mb smaller and does not work in this case
COPY --from=eclipse-temurin:17-jre $JAVA_HOME $JAVA_HOME
ENV PATH="${JAVA_HOME}/bin:${PATH}"

ENV PYTHONUNBUFFERED 1
ENV PYTHONDONTWRITEBYTECODE 1
ENV PYTHONWARNINGS="ignore::UserWarning"
ENV LITESTAR_DEBUG 1

RUN useradd -ms /bin/bash appuser

USER appuser



ENV PATH="$PATH:/home/appuser/.local/bin"

RUN pip install --upgrade pip

COPY requirements.txt /tmp/requirements.txt

RUN pip install --no-cache-dir -U -r /tmp/requirements.txt

WORKDIR /app

RUN pip install --upgrade pip
COPY requirements.txt .
RUN pip install -r requirements.txt

# copy project
COPY . .
 
USER root
 
RUN chown appuser:appuser -R  /app
 
USER appuser

#CMD ["litestar", "--app", "basic:app", "--host", "0.0.0.0", "--port", "8000", "run"]
CMD ["uvicorn", "basic:app", "--host", "0.0.0.0", "--port", "8000"]


EXPOSE 8000