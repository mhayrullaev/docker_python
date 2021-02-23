FROM python:3.9.1-buster

RUN mkdir -p /usr/src/app/
#Make a directory for our application
WORKDIR /usr/src/app/

#Install dependencies
#COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

#Copy our sourse code
COPY . /usr/src/app/

#Run the app
CMD ["python", "app.py"]