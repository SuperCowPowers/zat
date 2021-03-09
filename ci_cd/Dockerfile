# Grab a docker image with java and python
FROM python:3.8

# Install Java (for PySpark)
RUN apt-get update
RUN apt-get install -y default-jdk

# Setup our ENV vars
ENV INSTALL_DIR /app
ENV PYTHONUNBUFFERED=1

# Set our working directory
WORKDIR ${INSTALL_DIR}

# Update Pip
RUN pip install --upgrade pip

# Install all application dependencies
COPY ci_cd/requirements.txt requirements.txt
RUN pip install -r requirements.txt

# Copy all the code into the /app directory
COPY . .

# Pip install our software
RUN pip install -e .
