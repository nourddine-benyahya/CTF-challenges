FROM python:3.9-slim

# Hidden AI pattern: Fibonacci(7) = 13
EXPOSE 8000
RUN echo "Hidden pattern: 0 1 1 2 3 5 8 13" > /pattern.txt

WORKDIR /app
COPY public /app/public

CMD ["python", "-m", "http.server", "8000", "--directory", "/app/public"]