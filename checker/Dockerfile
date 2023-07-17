FROM python:3.11

# Install deps
RUN apt update && apt install -y build-essential sagemath

# Create user
RUN useradd -ms /bin/bash -u 1000 checker

RUN wget https://bootstrap.pypa.io/get-pip.py
RUN chmod +x get-pip.py
RUN sage-python get-pip.py --break-system-packages

USER checker
WORKDIR /checker

# Install all required dependencies for the checker.
COPY ./src/requirements.txt /checker/requirements.txt
RUN sage-python -m pip install -r requirements.txt --break-system-packages

COPY src/startup.sh /home/checker/.local/bin/gunicorn
USER root
RUN chmod 777 /home/checker/.local/bin/gunicorn
USER checker
# Copy all files into the container.
COPY ./src/ /checker/


ENTRYPOINT [ "/home/checker/.local/bin/gunicorn", "-c", "gunicorn.conf.py", "checker:app" ]