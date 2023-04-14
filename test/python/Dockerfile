# Use the official Python base image
FROM python:3.8-slim

# Set the working directory in the container
WORKDIR /app

# Copy the Flask app files to the container
COPY server.py /app/app.py

# Copy the images folder to the container
COPY ./images /app/images

# Install Flask and its dependencies
RUN pip install Flask

# Expose the port that the Flask app will run on
EXPOSE 5000

# Start the Flask app
CMD ["python", "app.py"]